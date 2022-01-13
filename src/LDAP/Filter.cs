using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

[assembly: InternalsVisibleTo("PSOpenADTests")]
namespace PSOpenAD.LDAP
{
    /// <summary>Exception used when failing to parse an LDAP filter.</summary>
    public class InvalidLDAPFilterException : FormatException
    {
        /// <summary>The full LDAP filter string that failed to parse.</c>
        public string Filter { get; } = "";

        /// <summary>The offset in <paramref name="Filter"/> where the fault starts.</summary>
        public int StartPosition { get; } = 0;

        /// <summary>The offset in <paramref name="Filter"/> where the fault ends.</summary>
        public int EndPosition { get; } = 0;

        public InvalidLDAPFilterException() { }

        public InvalidLDAPFilterException(string message) : base(message) { }

        public InvalidLDAPFilterException(string message, string filter, int startPosition, int endPosition)
            : base(message)
        {
            Filter = filter;
            StartPosition = startPosition;
            EndPosition = endPosition;
        }

        public InvalidLDAPFilterException(string message, Exception innerException) :
            base(message, innerException)
        { }
    }

    /// <summary>Base class for all LDAP filter classes that control how they are serialized.</summary>
    /// <remarks>
    /// The ASN.1 structure is defined as
    ///     Filter ::= CHOICE {
    ///             and             [0] SET SIZE (1..MAX) OF filter Filter,
    ///             or              [1] SET SIZE (1..MAX) OF filter Filter,
    ///             not             [2] Filter,
    ///             equalityMatch   [3] AttributeValueAssertion,
    ///             substrings      [4] SubstringFilter,
    ///             greaterOrEqual  [5] AttributeValueAssertion,
    ///             lessOrEqual     [6] AttributeValueAssertion,
    ///             present         [7] AttributeDescription,
    ///             approxMatch     [8] AttributeValueAssertion,
    ///             extensibleMatch [9] MatchingRuleAssertion,
    ///             ...  }
    /// </remarks>
    internal abstract class LDAPFilter
    {
        // The attribute name can either be an alpha number name (+ '-') or an OID string with optional options.
        private const string ATTRIBUTE_PATTERN =
            @"^(?:
  (?: # Alphanumeric with hyphen (must start with alpha)
    [a-zA-Z][a-zA-Z0-9\-]*
  )
  | # or
  (?: # OID
    (?:(?:[0-9])|(?:[1-9][0-9]*)) # number without leading 0 (except 0 itself)
    (?:\.(?:(?:[0-9])|(?:[1-9][0-9]*)))* # repeat but with . as separator
  )
)
# Optional attr options start with ; and are alphanumeric + -
(?:;[a-zA-Z0-9\-]+)*
$";

        /// <summary>Encode the filter to the AsnWriter provided.</summary>
        /// <param name="writer">The ASN.1 writer to encode the filter value to.</param>
        public abstract void ToBytes(AsnWriter writer);

        /// <summary>Reads an LDAP filter string and creates the parsed filter object.</summary>
        /// <param name="filter">The full LDAP filter that is being processed.</param>
        /// <returns>The LDAP filter that can be used with the LDAP API.</returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        public static LDAPFilter ParseFilter(string filter)
        {
            filter = filter.Trim();

            LDAPFilter filterObj = ParseFilter(filter.AsSpan(), 0, filter.Length, out var read);
            if (filter.Length != read)
            {
                throw new InvalidLDAPFilterException(
                    "Extra data found at filter end",
                    filter,
                    read,
                    filter.Length - read);
            }

            return filterObj;
        }

        /// <summary>Encodes the filter value into the raw bytes it represents.</summary>
        /// <param name="value">The value to encode.</param>
        /// <returns>The raw bytes of the encoded value.</returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        public static Memory<byte> EncodeSimpleFilterValue(string value)
        {
            return ParseFilterValue(value.AsSpan(), 0, value.Length, out var _);
        }

        /// <summary>Reads an LDAP filter string and creates the parsed filter objects.</summary>
        /// <remarks>
        /// This will parse the first LDAP filter enclosed with '()' or a single simple filter like 'attr=value'.
        /// Use the out read parameter to determine how much of the input filter was read and to determine if there
        /// is more to read based on the rules of the group it was contained in.
        /// </remarks>
        /// <param name="filter">The full LDAP filter that is being processed.</param>
        /// <param name="offset">The offset of the filter to process.</param>
        /// <param name="length">The length of the filter from the offset to process.</param>
        /// <param name="read">
        /// Outputs the number of chars that were read from the offset until the end of the current filter value.
        /// </param>
        /// <returns>The LDAP filter that can be used with the LDAP API.</returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        private static LDAPFilter ParseFilter(ReadOnlySpan<char> filter, int offset, int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.Slice(offset, length);

            int? parensStart = null;
            LDAPFilter? parsedFilter = null;
            for (read = 0; read < filterSpan.Length; read++)
            {
                char c = filterSpan[read];

                if (c == ' ')
                    continue;

                if (c == ')')
                {
                    if (parensStart == null)
                    {
                        // LDAP filter - ')'
                        throw new InvalidLDAPFilterException(
                            "Unbalanced closing ')' without a starting '('",
                            filter.ToString(),
                            offset + read,
                            offset + read + 1);
                    }

                    parensStart = null;
                    read++;
                    break;
                }
                else if (parensStart != null)
                {
                    // LDAP filter inside parens - '(objectClass=*)' or '(&(test)(value))'. Determine whether it is a
                    // simple value or conditional value and parse accordingly. First make sure there isn't a double
                    // filter like '((objectClass=*))' or that it didn't just parse one '(!(foo=*)!(bar=*))'.
                    if (parsedFilter != null)
                    {
                        throw new InvalidLDAPFilterException(
                            "Expected ')' to close current filter group",
                            filter.ToString(),
                            offset + read,
                            offset + read + 1);
                    }
                    else if (c == '(')
                    {
                        throw new InvalidLDAPFilterException(
                            "Nested '(' without filter condition",
                            filter.ToString(),
                            offset + read,
                            offset + read + 1);
                    }

                    int subFilterRead;
                    int subFilterOffset = offset + read;
                    int subFilterLength = length - read;
                    if (c == '&' || c == '|' || c == '!')
                    {
                        // LDAP filter = '(&(foo=bar)(hello=world))'
                        parsedFilter = ParseComplexFilter(filter, subFilterOffset, subFilterLength, out subFilterRead);
                    }
                    else
                    {
                        // LDAP filter = '(foo=bar)'
                        parsedFilter = ParseSimpleFilter(filter, subFilterOffset, subFilterLength, out subFilterRead);
                    }

                    // The length will either be at the end or just before the closing ) for this grouping but 1 still
                    // needs to be taken off as the current char is also read.
                    read += subFilterRead - 1;
                }
                else if (c == '(')
                {
                    parensStart = read;
                }
                else if (parsedFilter != null)
                {
                    // LDAP filter - (!(foo=bar)objectClass=*)
                    throw new InvalidLDAPFilterException(
                        "Expected ')' to close current filter group",
                        filter.ToString(),
                        offset + read,
                        offset + read + 1);
                }
                else
                {
                    // LDAP filter not surrounded by () - 'objectClass=*'
                    parsedFilter = ParseSimpleFilter(filter, offset + read, length - read, out var simpleRead);
                    read += simpleRead;
                    break;
                }
            }

            if (parensStart != null)
            {
                // LDAP filter - '(objectClass=*'
                throw new InvalidLDAPFilterException(
                    "Unbalanced starting '(' without a closing ')'",
                    filter.ToString(),
                    offset + (parensStart ?? 0),
                    offset + length);
            }

            if (parsedFilter == null)
            {
                // LDAP filter = '()'
                throw new InvalidLDAPFilterException(
                    "No filter found",
                    filter.ToString(),
                    offset,
                    offset + length);
            }

            return parsedFilter;
        }

        /// <summary>Reads the complex LDAP filter starting with <c>&amp;</c>, <c>|</c>, or <c>!</c>.</summary>
        /// <remarks>
        /// This will parse the complex LDAP filter until it reaches the end of the filter slice or up to but not
        /// including the <c>)</c> that closes the complex filter. The offset should correspond to the conditional
        /// character in the filter to start the processing from.
        /// </remarks>
        /// <param name="filter">The full LDAP filter that is being processed.</param>
        /// <param name="offset">The offset of the complex filter to process.</param>
        /// <param name="length">The length of the complex filter from the offset to process.</param>
        /// <param name="read">
        /// Outputs the number of chars that were read from the offset until the end of the current filter value.
        /// </param>
        /// <returns>The LDAP filter that can be used with the LDAP API.</returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        private static LDAPFilter ParseComplexFilter(ReadOnlySpan<char> filter, int offset, int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.Slice(offset, length);
            char complexType = filterSpan[0];

            List<LDAPFilter> parsedFilters = new();
            for (read = 1; read < filterSpan.Length; read++)
            {
                char c = filterSpan[read];

                if (c == ' ')
                    continue;

                if (c == '(')
                {
                    if (complexType == '!' && parsedFilters.Count == 1)
                    {
                        // LDAP filter - '!(foo=bar)(hello=*)...'
                        throw new InvalidLDAPFilterException(
                            "Multiple filters found for not '!' expression",
                            filter.ToString(),
                            offset,
                            offset + length - 1);
                    }

                    LDAPFilter parsedFilter = ParseFilter(filter, offset + read, length - read - 1,
                        out var filterRead);
                    parsedFilters.Add(parsedFilter);

                    // Subtract 1 as the current char was also read by ParseFilter.
                    read += filterRead - 1;
                }
                else if (c == ')')
                {
                    // read--; // Do not include the ending ')' in the read count.
                    break;
                }
                else if (parsedFilters.Count > 0)
                {
                    // LDAP filter - '&(foo=bar)hello=world'
                    throw new InvalidLDAPFilterException(
                        "Expecting ')' to end complex filter expression",
                        filter.ToString(),
                        offset,
                        offset + 1);
                }
                else
                {
                    // LDAP filter - '|foo=bar'
                    throw new InvalidLDAPFilterException(
                        "Expecting '(' to start after qualifier in complex filter expression",
                        filter.ToString(),
                        offset,
                        offset + 1);
                }
            }

            if (parsedFilters.Count == 0)
            {
                // LDAP filter - '&' '|' '!' (no actual data after the conditional).
                throw new InvalidLDAPFilterException(
                    "No filter value found after conditional",
                    filter.ToString(),
                    offset,
                    offset + length);
            }

            if (complexType == '!')
            {
                return new FilterNot(parsedFilters[0]);
            }
            else if (complexType == '&')
            {
                return new FilterAnd(parsedFilters.ToArray());
            }
            else
            {
                return new FilterOr(parsedFilters.ToArray());
            }
        }

        /// <summary>Reads the simple LDAP filter like <c>objectClass=user</c>.</summary>
        /// <remarks>
        /// This will parse the simple LDAP filter until it reaches the end of the filter slice or up to but not
        /// including the <c>)</c> that closes the filter. The offset should correspond to the first character in the
        /// filter to start the processing from.
        /// </remarks>
        /// <param name="filter">The full LDAP filter that is being processed.</param>
        /// <param name="offset">The offset of the simple filter to process.</param>
        /// <param name="length">The length of the simple filter from the offset to process.</param>
        /// <param name="read">
        /// Outputs the number of chars that were read from the offset until the end of the current filter value.
        /// </param>
        /// <returns>The LDAP filter that can be used with the LDAP API.</returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        private static LDAPFilter ParseSimpleFilter(ReadOnlySpan<char> filter, int offset, int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.Slice(offset, length);
            read = 0;

            int equalsIdx = filterSpan.IndexOf('=');
            if (equalsIdx == 0)
            {
                // LDAP filter - '=foo'
                throw new InvalidLDAPFilterException(
                    "Simple filter value must not start with '='",
                    filter.ToString(),
                    offset,
                    offset + 1);
            }
            else if (equalsIdx == -1)
            {
                // LDAP filter - 'foo'
                throw new InvalidLDAPFilterException(
                    "Simple filter missing '=' character",
                    filter.ToString(),
                    offset,
                    offset + length);
            }
            else if (equalsIdx == filterSpan.Length - 1)
            {
                // LDAP filter - 'foo='
                throw new InvalidLDAPFilterException(
                    "Simple filter value is not present after '='",
                    filter.ToString(),
                    offset,
                    offset + length);
            }

            char filterType = filterSpan[equalsIdx - 1];
            if (filterType == ':')
            {
                // LDAP extensible filter - 'foo:=...'
                FilterExtensibleMatch parsedFilter = ParseFilterExtensibleMatch(filter, offset, length, out var filterRead);
                read += filterRead;

                return parsedFilter;
            }
            else
            {
                int attributeEnd = equalsIdx;
                if (filterType == '<' || filterType == '>' || filterType == '~')
                    attributeEnd--;

                string attribute = filterSpan[..attributeEnd].ToString();
                if (!Regex.Match(
                    attribute,
                    ATTRIBUTE_PATTERN,
                    RegexOptions.Compiled | RegexOptions.IgnorePatternWhitespace
                ).Success)
                {
                    throw new InvalidLDAPFilterException(
                        "Invalid filter attribute value",
                        filter.ToString(),
                        offset,
                        offset + attributeEnd);
                }

                read += equalsIdx + 1;
                int valueOffset = offset + read;

                ReadOnlySpan<char> value = filterSpan[read..];
                int valueLength = value.IndexOf(')');
                if (valueLength == -1)
                    valueLength = value.Length;
                value = value[..valueLength];

                if (filterType == '<' || filterType == '>' || filterType == '~')
                {
                    Memory<byte> rawValue = ParseFilterValue(filter, valueOffset, value.Length, out var valueRead);
                    read += valueRead;

                    if (filterType == '<')
                    {
                        return new FilterGreaterOrEqual(attribute, rawValue);
                    }
                    else if (filterType == '>')
                    {
                        return new FilterGreaterOrEqual(attribute, rawValue);
                    }
                    else
                    {
                        return new FilterApproxMatch(attribute, rawValue);
                    }
                }
                else if (value.ToString() == "*")
                {
                    read++;
                    return new FilterPresent(attribute);
                }
                else if (value.Contains('*'))
                {
                    (var initial, var any, var final) = ParseFilterSubstringsValue(filter, valueOffset, value.Length,
                        out var substringRead);
                    read += substringRead;

                    return new FilterSubstrings(attribute, initial, any.ToArray(), final);
                }
                else
                {
                    Memory<byte> rawValue = ParseFilterValue(filter, valueOffset, value.Length, out var valueRead);
                    read += valueRead;

                    return new FilterEquality(attribute, rawValue);
                }
            }
        }

        /// <summary>Reads the extensible LDAP filter like <c>objectClass:=user</c>.</summary>
        /// <remarks>
        /// This will parse the extensible LDAP filter until it reaches the end of the filter slice or up to but not
        /// including the <c>)</c> that closes the filter. The offset should correspond to the first character in the
        /// filter to start the processing from.
        /// </remarks>
        /// <param name="filter">The full LDAP filter that is being processed.</param>
        /// <param name="offset">The offset of the extensible filter to process.</param>
        /// <param name="length">The length of the extensible filter from the offset to process.</param>
        /// <param name="read">
        /// Outputs the number of chars that were read from the offset until the end of the current filter value.
        /// </param>
        /// <returns>The LDAP filter that can be used with the LDAP API.</returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        private static FilterExtensibleMatch ParseFilterExtensibleMatch(ReadOnlySpan<char> filter, int offset,
            int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.Slice(offset, length);
            read = 0;

            int equalsIdx = filterSpan.IndexOf('=');
            if (equalsIdx == 1)
            {
                // LDAP filter - ':=value'
                throw new InvalidLDAPFilterException(
                    "Extensible filter must define an attribute name or rule before ':='",
                    filter.ToString(),
                    offset,
                    offset + equalsIdx);
            }

            ReadOnlySpan<char> header = filterSpan[..(equalsIdx + 1)];
            ReadOnlySpan<char> value = filterSpan[(equalsIdx + 1)..];

            string? attribute = null;
            int colonIdx = header.IndexOf(':');
            if (colonIdx != 0)
            {
                attribute = header[..colonIdx].ToString();
                if (!Regex.Match(
                    attribute,
                    ATTRIBUTE_PATTERN,
                    RegexOptions.Compiled | RegexOptions.IgnorePatternWhitespace
                ).Success)
                {
                    throw new InvalidLDAPFilterException(
                        "Invalid extensible filter attribute value",
                        filter.ToString(),
                        offset,
                        offset + colonIdx);
                }

                header = header[(colonIdx + 1)..];
                read += colonIdx + 1;

                colonIdx = header.IndexOf(':');
            }
            else
            {
                // If not attribute was given then the first : needs to be removed before continuing the scan.
                header = header[1..];
                read++;
            }

            colonIdx = header.IndexOf(':');
            bool dnAttributes = false;
            if (colonIdx == 2 && header[..2].ToString() == "dn")
            {
                dnAttributes = true;
                header = header[(colonIdx + 1)..];
                read += colonIdx + 1;

                colonIdx = header.IndexOf(':');
            }

            string? rule = null;
            if (colonIdx != -1 && colonIdx != 0)
            {
                rule = header[..colonIdx].ToString();
                header = header[(colonIdx + 1)..];
                read += colonIdx + 1;

                colonIdx = header.IndexOf(':');
            }

            if (attribute == null && rule == null)
            {
                // LDAP filter - ':dn:=value'
                throw new InvalidLDAPFilterException(
                    "Extensible filter must define the attribute, rule or both",
                    filter.ToString(),
                    offset,
                    offset + equalsIdx);
            }

            if (header.Length != 1 || (header.Length == 1 && header[0] != '='))
            {
                // LDAP filter - ':rule:extra-data:=value'
                throw new InvalidLDAPFilterException(
                    "Extra data found in extensible filter key",
                    filter.ToString(),
                    offset + read,
                    offset + equalsIdx);
            }
            read++; // The = was already read

            Memory<byte> rawValue = ParseFilterValue(filter, offset + read, length - read, out var valueRead);
            read += valueRead;

            return new FilterExtensibleMatch(rule, attribute, rawValue, dnAttributes);
        }

        /// <summary>Reads the simple LDAP substrings filter value and returns each component.</summary>
        /// <remarks>
        /// This will parse the simple LDAP substrings filter value like <c>user*name</c> and return the initial,
        /// middle, and end components that comprise the value. The offset should correspond to the first character in
        /// the filter value (after the <c>=</c>) to start the processing from. The length should be the length of the
        /// value up to but not including the end <c>)</c> or the end of the filter if not more data is left.
        /// </remarks>
        /// <param name="filter">The full LDAP filter that is being processed.</param>
        /// <param name="offset">The offset of the simple filter value to process.</param>
        /// <param name="length">The length of the simple filter value from the offset to process.</param>
        /// <param name="read">
        /// Outputs the number of chars that were read from the offset until the end of the current filter value.
        /// </param>
        /// <returns>
        /// A tuple comprised of:
        ///     The initial entry before the first <c>*</c> or null if the value starts with <c>*</c>.
        ///     All values after the first and before the last <c>*</c>.
        ///     The final entry after the last <c>*</c> or null if the value ends with <c>*</c>.
        /// </returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        private static (Memory<byte>?, List<Memory<byte>>, Memory<byte>?) ParseFilterSubstringsValue(
            ReadOnlySpan<char> filter, int offset, int length, out int read)
        {
            read = 0;

            Memory<byte>? initial = null;
            List<Memory<byte>> any = new();
            Memory<byte>? final = null;

            while (read < length)
            {
                Memory<byte> value = ParseFilterValue(filter, offset + read, length - read,
                    out var valueRead, endWithAsterisk: true);
                read += valueRead;

                if (value.Length == 0)
                {
                    if (read == length)
                    {
                        // Ends with '*' no final value set
                        // LDAP filter - 'attr=foo*'
                        break;
                    }
                    else if (read != valueRead)
                    {
                        // LDAPFilter - 'attr=test**value'
                        throw new InvalidLDAPFilterException(
                            "Cannot have 2 consecutive '*' in substring filter",
                            filter.ToString(),
                            offset + read,
                            offset + read + 1);
                    }

                    // Else starts with initial '*' no initial value set.
                    // LDAP filter - 'attr=*foo'
                }
                else if (read == valueRead)
                {
                    // Value before first '*' - 'attr=foo*...'
                    initial = value;
                }
                else if (read == length)
                {
                    // Value until the end - 'attr=*foo'
                    final = value;
                    break;
                }
                else
                {
                    // After the first '*' and before the last '*'
                    any.Add(value);
                }

                read++; // Include the asterisk in the count
            }

            return (initial, any, final);
        }

        /// <summary>Encodes the simple LDAP filter value to the bytes required..</summary>
        /// <remarks>
        /// This will parse the simple LDAP filter value string to the encoded byte format required. It will correctly
        /// encode escaped sequences like <c>\00</c> where <c>00</c> is the hex string representing the bytes for that
        /// value. It also validates that reserved characters like NULL, <c>(</c>, or <c>*</c> are in the value without
        /// being first escaped. The offset should correspond to the first character in the value (after the <c>=</c>)
        /// to start the processing from.
        /// </remarks>
        /// <param name="filter">The LDAP filter value that is being processed.</param>
        /// <param name="offset">The offset of the simple filter value to process.</param>
        /// <param name="length">The length of the simple filter value from the offset to process.</param>
        /// <param name="read">
        /// Outputs the number of chars that were read from the offset until the end of the current filter value.
        /// </param>
        /// <returns>The byte array that is the value encoded for network transmission.</returns>
        /// <exception cref="InvalidLDAPFilterException">Invalid LDAP filter provided.</exception>
        private static Memory<byte> ParseFilterValue(ReadOnlySpan<char> filter, int offset, int length, out int read,
            bool endWithAsterisk = false)
        {
            ReadOnlySpan<char> value = filter.Slice(offset, length);

            // Due to escaping taking more chars than the raw value we can safely use that to build the initial
            // memory block. Escaping is simply \00 where the following 2 values are the hex representation of the raw
            // bytes it represents.
            Memory<byte> encodedValue = new(new byte[Encoding.UTF8.GetByteCount(value)]);
            Span<byte> encodedSpan = encodedValue.Span;

            int count = 0;
            for (read = 0; read < value.Length; read++)
            {
                char c = value[read];

                if (c == '\\')
                {
                    if (read + 2 < value.Length)
                    {
                        string escapedHex = value.Slice(read + 1, 2).ToString();
                        if (Regex.Match(escapedHex, "[a-fA-F0-9]{2}", RegexOptions.Compiled).Success)
                        {
                            encodedSpan[count] = Convert.ToByte(escapedHex, 16);
                            read += 2;
                            count++;
                        }
                        else
                        {
                            // LDAP filter - 'objectClass=foo\1Z'
                            throw new InvalidLDAPFilterException(
                                $"Invalid hex characters following \\ '{escapedHex}'",
                                filter.ToString(),
                                offset + read + 1,
                                offset + read + 3);
                        }
                    }
                    else
                    {
                        // LDAP filter - 'objectClass=\1'
                        throw new InvalidLDAPFilterException(
                            "Not enough escape characters following \\",
                            filter.ToString(),
                            offset + read,
                            offset + length);
                    }
                }
                else if (c == ')' || (c == '*' && endWithAsterisk))
                {
                    // The filter ends when ')' is encountered or no more chars are left. This is the former case and
                    // the ')' should not be included in the final count as it's part of the parent filter that
                    // contains the value. If endWithAsterisk we also consider that the end of the value and is used
                    // to note the end of a substring filter component.
                    // read--;
                    break;
                }
                else if (c == '\0' || c == '(' || c == '*')
                {
                    string needed = "\\" + BitConverter.ToString(new[] { (byte)c });
                    throw new InvalidLDAPFilterException(
                        $"LDAP filter value contained unescaped char '{c}', use '{needed}' instead",
                        filter.ToString(),
                        offset + read,
                        offset + read + 1);
                }
                else
                {
                    count += Encoding.UTF8.GetBytes(value.Slice(read, 1), encodedSpan[read..]);
                }
            }

            return encodedValue[..count];
        }
    }

    /// <summary>Used as a base class for filter that encode an attribute and value.</summary>
    internal abstract class FilterAttributeValue : LDAPFilter
    {
        /// <summary>The LDAP attribute this rule is for.</summary>
        public string Attribute { get; internal set; }

        /// <summary>The value for the attribute to filter by.</summary>
        public Memory<byte> Value { get; internal set; }

        /// <summary>The ASN.1 tag value used when encoding the filter.</summary>
        public abstract int TagValue { get; }

        internal FilterAttributeValue(string attribute, Memory<byte> value)
        {
            Attribute = attribute;
            Value = value;
        }

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, TagValue, true));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute));
            writer.WriteOctetString(Value.Span);
        }
    }

    /// <summary>Combines two filters together using an AND condition.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7">4.5.1.7. SearchRequest.filter</see>
    internal class FilterAnd : LDAPFilter
    {
        /// <summary>The LDAP filters to AND together.</summary>
        public LDAPFilter[] Filters { get; internal set; }

        public FilterAnd(LDAPFilter[] filters) => Filters = filters;

        public override void ToBytes(AsnWriter writer)
        {
            // Filter ::= CHOICE {
            //     and [0] SET SIZE (1..MAX) OF filter Filter,
            //     ... }
            using AsnWriter.Scope _ = writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            foreach (LDAPFilter filter in Filters)
            {
                filter.ToBytes(writer);
            }
        }
    }

    /// <summary>Combines two filters together using an OR condition.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7">4.5.1.7. SearchRequest.filter</see>
    internal class FilterOr : LDAPFilter
    {
        /// <summary>The LDAP filters to OR together.</summary>
        public LDAPFilter[] Filters { get; internal set; }

        public FilterOr(LDAPFilter[] filters) => Filters = filters;

        public override void ToBytes(AsnWriter writer)
        {
            // Filter ::= CHOICE {
            //     or [1] SET SIZE (1..MAX) OF filter Filter,
            //     ... }
            using AsnWriter.Scope _ = writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, true));
            foreach (LDAPFilter filter in Filters)
            {
                filter.ToBytes(writer);
            }
        }
    }

    /// <summary>A filter that checks whether the filter applied is not true.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7">4.5.1.7. SearchRequest.filter</see>
    internal class FilterNot : LDAPFilter
    {
        /// <summary>The filter to check whether it is not equal.</summary>
        public LDAPFilter Filter { get; internal set; }

        public FilterNot(LDAPFilter filter) => Filter = filter;

        public override void ToBytes(AsnWriter writer)
        {
            // Filter ::= CHOICE {
            //     not [2] Filter,
            //     ... }
            using AsnWriter.Scope _ = writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 2, true));
            Filter.ToBytes(writer);
        }
    }

    /// <summary>A filter used to check if the attribute is equal to the value specified.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7.1">4.5.1.7.1. SearchRequest.equalityMatch</see>
    internal class FilterEquality : FilterAttributeValue
    {
        public override int TagValue => 3;

        public FilterEquality(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    /// <summary>A filter used to check if the attribute value matches the substrings pattern specified.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7.2">4.5.1.7.2. SearchRequest.substrings</see>
    internal class FilterSubstrings : LDAPFilter
    {
        /// <summary>The attribute to check.</summary>
        public string Attribute { get; internal set; }

        /// <summary>What the value must start with or <c>null</c> for any starting value.</summary>
        public Memory<byte>? Initial { get; internal set; }

        /// <summary>Any matching components in order that the value must match with.</summary>
        public Memory<byte>[] Any { get; internal set; }

        /// <summary>What the value must end with or <c>null</c> for any ending value.</summary>
        public Memory<byte>? Final { get; internal set; }

        public FilterSubstrings(string attribute, Memory<byte>? initial, Memory<byte>[] any, Memory<byte>? final)
        {
            Attribute = attribute;
            Initial = initial;
            Any = any;
            Final = final;
        }

        public override void ToBytes(AsnWriter writer)
        {
            // Filter ::= CHOICE {
            //     substrings [4] SubstringFilter,
            //     ... }
            // SubstringFilter ::= SEQUENCE {
            //         type           AttributeDescription,
            //         substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
            //             initial [0] AssertionValue,  -- can occur at most once
            //             any     [1] AssertionValue,
            //             final   [2] AssertionValue } -- can occur at most once
            //         }
            using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 4, true));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute));

            using AsnWriter.Scope _2 = writer.PushSequence();
            if (Initial != null)
                writer.WriteOctetString(((Memory<byte>)Initial).Span, new Asn1Tag(TagClass.ContextSpecific, 0, false));

            foreach (Memory<byte> any in Any)
                writer.WriteOctetString(any.Span, new Asn1Tag(TagClass.ContextSpecific, 1, false));

            if (Final != null)
                writer.WriteOctetString(((Memory<byte>)Final).Span, new Asn1Tag(TagClass.ContextSpecific, 2, false));
        }
    }

    /// <summary>A filter used to check if the attribute is greater than or equal to the value specified.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7.3">4.5.1.7.3. SearchRequest.greaterOrEqual</see>
    internal class FilterGreaterOrEqual : FilterAttributeValue
    {
        public override int TagValue => 5;

        public FilterGreaterOrEqual(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    /// <summary>A filter used to check if the attribute is less than or equal to the value specified.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7.4">4.5.1.7.4. SearchRequest.lessOrEqual</see>
    internal class FilterLessOrEqual : FilterAttributeValue
    {
        public override int TagValue => 6;

        public FilterLessOrEqual(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    /// <summary>A filter used to check if the attribute exists on the entry scanned.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7.5">4.5.1.7.5. SearchRequest.present</see>
    internal class FilterPresent : LDAPFilter
    {
        /// <summary>The attribute that must exist on the entry.</summary>
        public string Attribute { get; internal set; }

        public FilterPresent(string attribute) => Attribute = attribute;

        public override void ToBytes(AsnWriter writer)
        {
            // Filter ::= CHOICE {
            //     present [7] AttributeDescription,
            //     ... }
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute),
                new Asn1Tag(TagClass.ContextSpecific, 7, false));
        }
    }

    /// <summary>A filter used to check if the attribute has an approximate match to the value specified.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7.6">4.5.1.7.6. SearchRequest.approxMatch</see>
    internal class FilterApproxMatch : FilterAttributeValue
    {
        public override int TagValue => 8;

        public FilterApproxMatch(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    /// <summary>A complex filter that provides extra control over how a value is matched on an attribute.</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.7.7">4.5.1.7.7. SearchRequest.extensibleMatch</see>
    internal class FilterExtensibleMatch : LDAPFilter
    {
        /// <summary>
        /// The rule used by the server to match the attribute values with the <paramref="Value"/> specified in the
        /// rule. This and/or <paramref="Attribute"/> must be specified.
        /// </summary>
        public string? MatchingRule { get; internal set; }

        /// <summary>The attribute to match with, this and/or <paramref="MatchingRule"/> must be specified.</summary>
        public string? Attribute { get; internal set; }

        /// <summary>The value to compare with.</summary>
        public Memory<byte> Value { get; internal set; }

        /// <summary>Include DistinguishedName attributes in the search criteria.</summary>
        public bool DNAttributes { get; internal set; }

        public FilterExtensibleMatch(string? matchingRule, string? attribute, Memory<byte> value, bool dnAttributes)
        {
            MatchingRule = matchingRule;
            Attribute = attribute;
            Value = value;
            DNAttributes = dnAttributes;
        }

        public override void ToBytes(AsnWriter writer)
        {
            // Filter ::= CHOICE {
            //     extensibleMatch [9] MatchingRuleAssertion,
            //     ... }
            // MatchingRuleAssertion ::= SEQUENCE {
            //         matchingRule    [1] MatchingRuleId OPTIONAL,
            //         type            [2] AttributeDescription OPTIONAL,
            //         matchValue      [3] AssertionValue,
            //         dnAttributes    [4] BOOLEAN DEFAULT FALSE }
            using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 9, true));

            if (MatchingRule != null)
                writer.WriteOctetString(Encoding.UTF8.GetBytes(MatchingRule), new Asn1Tag(TagClass.ContextSpecific, 1, false));

            if (Attribute != null)
                writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute), new Asn1Tag(TagClass.ContextSpecific, 2, false));

            writer.WriteOctetString(Value.Span, new Asn1Tag(TagClass.ContextSpecific, 3, false));

            if (DNAttributes)
                writer.WriteBoolean(DNAttributes, new Asn1Tag(TagClass.ContextSpecific, 4, false));
        }
    }
}
