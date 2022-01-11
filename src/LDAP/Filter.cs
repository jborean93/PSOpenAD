using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;
using System.Text.RegularExpressions;

namespace PSOpenAD.LDAP
{
    public class InvalidLDAPFilterException : FormatException
    {
        public string Filter { get; } = "";
        public int StartPosition { get; } = 0;
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

    internal abstract class LDAPFilter
    {
        public abstract void ToBytes(AsnWriter writer);

        /// <summary>Reads an LDAP filter string and creates the parsed filter object.</summary>
        /// <param name="filter">The full LDAP filter that is being processed.</param>
        /// <returns>The LDAP filter that can be used with the LDAP API.</returns>
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
                return new FilterNot(parsedFilters[0]);

            else if (complexType == '&')
                return new FilterAnd(parsedFilters.ToArray());

            else
                return new FilterOr(parsedFilters.ToArray());
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
        private static LDAPFilter ParseSimpleFilter(ReadOnlySpan<char> filter, int offset, int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.Slice(offset, length);
            read = 0;

            // int closingParen = FindClosingParen(filterSpan);
            // if (closingParen == -1)
            // {
            //     throw new InvalidLDAPFilterException("Failed to find closing parent for filter");
            // }
            // filterSpan = filterSpan[..closingParen];
            // read = closingParen;

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

            // The attribute name can either be an alpha number name (+ '-') or an OID string. This pattern will
            // validate this is the case.
            const string attributePattern =
                @"^((?:[a-zA-Z][a-zA-Z0-9\-]*)|(?:[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*))((?:;[a-zA-Z0-9\-]+)*)$";

            char filterType = filterSpan[equalsIdx - 1];
            if (filterType == ':')
            {
                // LDAP extensible filter - 'foo:=...'
                // FIXME: implement
                throw new NotImplementedException();
            }
            else
            {
                int attributeEnd = equalsIdx;
                if (filterType == '<' || filterType == '>' || filterType == '~')
                    attributeEnd--;

                string attribute = filterSpan[..attributeEnd].ToString();
                if (!Regex.Match(attribute, attributePattern, RegexOptions.Compiled).Success)
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
                        return new FilterGreaterOrEqual(attribute, rawValue);

                    else if (filterType == '>')
                        return new FilterGreaterOrEqual(attribute, rawValue);

                    else
                        return new FilterApproxMatch(attribute, rawValue);
                }
                else if (value.ToString() == "*")
                {
                    read++;
                    return new FilterPresent(attribute);
                }
                else if (value.Contains('*'))
                {
                    // FIXME: determine if initial or end
                    Memory<byte>? first = null;
                    List<Memory<byte>> rawValues = new();
                    Memory<byte>? last = null;

                    while (value.Length > 0)
                    {
                        int idx = value.IndexOf('*');
                        int endIncrement = 1;
                        if (idx == -1)
                        {
                            idx = value.Length;
                            endIncrement = 0;
                        }

                        Memory<byte> rawValue = ParseFilterValue(filter, offset + read, idx, out var valueRead);
                        rawValues.Add(rawValue);
                        read += valueRead + endIncrement;

                        value = value[(valueRead + endIncrement)..];
                    }

                    return new FilterSubstrings(attribute, first, rawValues.ToArray(), last);
                }
                else
                {
                    Memory<byte> rawValue = ParseFilterValue(filter, valueOffset, value.Length, out var valueRead);
                    read += valueRead;

                    return new FilterEquality(attribute, rawValue);
                }
            }
        }

        private static Memory<byte> ParseFilterValue(ReadOnlySpan<char> filter, int offset, int length, out int read)
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
                else if (c == ')')
                {
                    // The filter ends when ')' is encountered or no more chars are left. This is the former case and
                    // the ')' should not be included in the final count as it's part of the parent filter that
                    // contains the value.
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

    internal abstract class FilterAttributeValue : LDAPFilter
    {
        public string Attribute { get; internal set; }
        public Memory<byte> Value { get; internal set; }

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

    internal class FilterAnd : LDAPFilter
    {
        public LDAPFilter[] Filters { get; internal set; }

        public FilterAnd(LDAPFilter[] filters) => Filters = filters;

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            foreach (LDAPFilter filter in Filters)
            {
                filter.ToBytes(writer);
            }
        }
    }

    internal class FilterOr : LDAPFilter
    {
        public LDAPFilter[] Filters { get; internal set; }

        public FilterOr(LDAPFilter[] filters) => Filters = filters;

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 1, true));
            foreach (LDAPFilter filter in Filters)
            {
                filter.ToBytes(writer);
            }
        }
    }

    internal class FilterNot : LDAPFilter
    {
        public LDAPFilter Filter { get; internal set; }

        public FilterNot(LDAPFilter filter) => Filter = filter;

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 2, true));
            Filter.ToBytes(writer);
        }
    }

    internal class FilterEquality : FilterAttributeValue
    {
        public override int TagValue => 3;

        public FilterEquality(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    internal class FilterSubstrings : LDAPFilter
    {
        public string Attribute { get; internal set; }
        public Memory<byte>? Initial { get; internal set; }
        public Memory<byte>[] Any { get; internal set; }
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
            /*
                    SubstringFilter ::= SEQUENCE {
            type    AttributeDescription,
            -- initial and final can occur at most once
            substrings    SEQUENCE SIZE (1..MAX) OF substring CHOICE {
             initial        [0] AssertionValue,
             any            [1] AssertionValue,
             final          [2] AssertionValue } }
            */
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

    internal class FilterGreaterOrEqual : FilterAttributeValue
    {
        public override int TagValue => 5;

        public FilterGreaterOrEqual(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    internal class FilterLessOrEqual : FilterAttributeValue
    {
        public override int TagValue => 6;

        public FilterLessOrEqual(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    internal class FilterPresent : LDAPFilter
    {
        public string Attribute { get; internal set; }

        public FilterPresent(string attribute) => Attribute = attribute;

        public override void ToBytes(AsnWriter writer)
        {
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute),
                new Asn1Tag(TagClass.ContextSpecific, 7, false));
        }
    }

    internal class FilterApproxMatch : FilterAttributeValue
    {
        public override int TagValue => 8;

        public FilterApproxMatch(string attribute, Memory<byte> value) : base(attribute, value) { }
    }

    internal class FilterExtensibleMatch : LDAPFilter
    {
        public string MatchingRule { get; internal set; }
        public string Attribute { get; internal set; }
        public string Value { get; internal set; }
        public bool DNAttributes { get; internal set; }

        public FilterExtensibleMatch(string matchingRule, string attribute, string value, bool dnAttributes)
        {
            MatchingRule = matchingRule;
            Attribute = attribute;
            Value = value;
            DNAttributes = dnAttributes;
        }

        public override void ToBytes(AsnWriter writer)
        {
            throw new NotImplementedException();
        }
    }
}
