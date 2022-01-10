using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;
using System.Text.RegularExpressions;

namespace PSOpenAD.LDAP
{
    public class InvalidLDAPFilterException : FormatException
    {
        public InvalidLDAPFilterException() { }

        public InvalidLDAPFilterException(string message) : base(message) { }

        public InvalidLDAPFilterException(string message, Exception innerException) :
            base(message, innerException)
        { }

        internal static InvalidLDAPFilterException FromFilterSubset(string filter, int offset, int length)
        {
            return new InvalidLDAPFilterException("Invalid LDAP filter");
        }
    }

    internal abstract class LDAPFilter
    {
        public abstract void ToBytes(AsnWriter writer);

        public static LDAPFilter ParseFilter(string filter, int offset, int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.AsSpan().Slice(offset, length);

            bool inParens = false;
            LDAPFilter? parsedFilter = null;
            for (read = 0; read < filterSpan.Length; read++)
            {
                char c = filterSpan[read];

                if (c == ' ')
                    continue;

                if (c == ')')
                {
                    if (!inParens)
                        throw new InvalidLDAPFilterException("closing ) without a starting (");

                    inParens = false;
                    continue;
                }
                else if (inParens)
                {
                    int subFilterRead;

                    if (c == '(')
                        throw new InvalidLDAPFilterException("nested ( without condition");

                    if (c == '&' || c == '|' || c == '!')
                        parsedFilter = ParseComplexFilter(filter, read, filter.Length - read, out subFilterRead);

                    else
                        parsedFilter = ParseSimpleFilter(filter, read, filter.Length - read, out subFilterRead);

                    read += subFilterRead;
                    continue;
                }

                if (parsedFilter != null)
                    throw new InvalidLDAPFilterException("Extra data found in filter");

                if (c == '(')
                {
                    inParens = true;
                }
                else
                {
                    parsedFilter = ParseSimpleFilter(filter, read, filter.Length - read, out var simpleRead);
                    read += simpleRead;
                }
            }

            if (parsedFilter == null)
                throw new InvalidLDAPFilterException("No filter found");

            return parsedFilter;
        }

        internal static LDAPFilter ParseComplexFilter(string filter, int offset, int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.AsSpan().Slice(offset, length);

            if (filterSpan.Length == 0)
                throw new InvalidLDAPFilterException("Unexpected end");

            char complexType = filterSpan[0];

            List<LDAPFilter> parsedFilters = new List<LDAPFilter>();

            for (read = 1; read < filterSpan.Length; read++)
            {
                char c = filterSpan[read];

                if (c == '(')
                {
                    if (complexType == '!' && parsedFilters.Count == 1)
                        throw new InvalidLDAPFilterException("Multiple filters found for not expression");

                    int closingParen = FindClosingParen(filterSpan[read..]);
                    if (closingParen == -1)
                        throw new InvalidLDAPFilterException("Failed to find closing parent for filter");

                    parsedFilters.Add(ParseFilter(filter, offset + read, closingParen, out var filterRead));
                    read += filterRead;
                }
                else if (c == ')')
                {
                    break;
                }
                else
                {
                    throw new InvalidLDAPFilterException("Expecting ( or ) in complex expression");
                }
            }

            if (parsedFilters.Count == 0)
                throw new InvalidLDAPFilterException("No filter found");

            if (complexType == '!')
                return new FilterNot(parsedFilters[0]);

            else if (complexType == '&')
                return new FilterAnd(parsedFilters.ToArray());

            else
                return new FilterOr(parsedFilters.ToArray());
        }

        internal static LDAPFilter ParseSimpleFilter(string filter, int offset, int length, out int read)
        {
            ReadOnlySpan<char> filterSpan = filter.AsSpan().Slice(offset, length);
            int closingParen = FindClosingParen(filterSpan);
            if (closingParen == -1)
                throw new InvalidLDAPFilterException("Failed to find closing parent for filter");

            filterSpan = filterSpan[..closingParen];
            read = closingParen;

            int equalsIdx = filterSpan.IndexOf('=');
            if (equalsIdx == 0)
                throw new InvalidLDAPFilterException("filter value must not start with =");

            else if (equalsIdx == -1)
                throw new InvalidLDAPFilterException("simple filter missing = value");

            else if (equalsIdx == filterSpan.Length - 1)
                throw new InvalidLDAPFilterException("filter value is not present after =");

            /*
                The attribute name follows this syntax. It can be the name or OID with optional semicolon delimited
                options.

                attributedescription = attributetype options
                attributetype = oid
                options = *( SEMI option )
                option = 1*keychar
            */
            const string attributePattern =
                @"^((?:[a-zA-Z][a-zA-Z0-9\-]*)|(?:[0-2](?:(?:\.0)|(?:\.[1-9][0-9]*))*))((?:;[a-zA-Z0-9\-]+)*)$";

            char filterType = filterSpan[equalsIdx - 1];
            if (filterType == ':')
            {
                throw new NotImplementedException();
            }
            else
            {
                int attributeEnd = equalsIdx;
                if (filterType == '<' || filterType == '>' || filterType == '~')
                    attributeEnd--;

                string attribute = filterSpan[..attributeEnd].ToString();
                if (!Regex.Match(attribute, attributePattern, RegexOptions.Compiled).Success)
                    throw new InvalidLDAPFilterException("invalid ldap attribute value");

                ReadOnlySpan<char> value = filterSpan[(equalsIdx + 1)..];
                Memory<byte> rawValue = ParseFilterValue(value);
                if (filterType == '<')
                    return new FilterGreaterOrEqual(attribute, rawValue);

                else if (filterType == '>')
                    return new FilterGreaterOrEqual(attribute, rawValue);

                else if (filterType == '~')
                    return new FilterApproxMatch(attribute, rawValue);

                else if (value == "*")
                    return new FilterPresent(attribute);

                else if (value.Contains('*')) // FIXME: Ignore \*
                    throw new NotImplementedException(); // substrings

                else
                    return new FilterEquality(attribute, rawValue);
            }

            throw new NotImplementedException();
        }

        private static int FindClosingParen(ReadOnlySpan<char> value)
        {
            int inside = 1;

            for (int i = 1; i < value.Length; i++)
            {
                char c = value[i];

                if (c == '\\')
                    i++; // The next char is escaped so skip that check

                else if (c == '(')
                    inside++;

                else if (c == ')')
                    inside--;

                if (inside == 0)
                    return i;
            }

            return -1;
        }

        internal static Memory<byte> ParseFilterValue(ReadOnlySpan<char> value)
        {
            // Due to escaping taking more chars than the raw value we can safely use that to build the initial
            // memory block. Escaping is simply \00 where the following 2 values are the hex representation of the raw
            // bytes it represents.
            Memory<byte> encodedValue = new(new byte[Encoding.UTF8.GetByteCount(value)]);
            Span<byte> encodedSpan = encodedValue.Span;

            int count = 0;
            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];

                if (c == '\\')
                {
                    if (i + 2 < value.Length)
                    {
                        string escapedHex = value.Slice(i + 1, 2).ToString();
                        if (Regex.Match(escapedHex, "[a-fA-F0-9]{2}", RegexOptions.Compiled).Success)
                        {
                            encodedSpan[count] = Convert.ToByte(escapedHex, 16);
                            i += 2;
                            count++;
                        }
                        else
                        {
                            throw new InvalidLDAPFilterException($"Invalid hex characters following \\ {escapedHex}");
                        }
                    }
                    else
                    {
                        throw new InvalidLDAPFilterException("Not enough escape characters");
                    }
                }
                else
                {
                    count += Encoding.UTF8.GetBytes(value.Slice(i, 1), encodedSpan[i..]);
                }
            }

            return encodedValue[..count];
        }
    }

    internal class FilterAnd : LDAPFilter
    {
        public LDAPFilter[] Filters { get; internal set; }

        public FilterAnd(LDAPFilter[] filters) => Filters = filters;

        public override void ToBytes(AsnWriter writer)
        {
            throw new NotImplementedException();
        }
    }

    internal class FilterOr : LDAPFilter
    {
        public LDAPFilter[] Filters { get; internal set; }

        public FilterOr(LDAPFilter[] filters) => Filters = filters;

        public override void ToBytes(AsnWriter writer)
        {
            throw new NotImplementedException();
        }
    }

    internal class FilterNot : LDAPFilter
    {
        public LDAPFilter Filter { get; internal set; }

        public FilterNot(LDAPFilter filter) => Filter = filter;

        public override void ToBytes(AsnWriter writer)
        {
            throw new NotImplementedException();
        }
    }

    internal class FilterEquality : LDAPFilter
    {
        public string Attribute { get; internal set; }
        public Memory<byte> Value { get; internal set; }

        public FilterEquality(string attribute, Memory<byte> value)
        {
            Attribute = attribute;
            Value = value;
        }

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 3, true));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute));
            writer.WriteOctetString(Value.Span);
        }
    }

    internal class FilterSubstrings : LDAPFilter
    {
        public string Attribute { get; internal set; }
        public string[] Elements { get; internal set; }

        public FilterSubstrings(string attribute, string[] elements)
        {
            Attribute = attribute;
            Elements = elements;
        }

        public override void ToBytes(AsnWriter writer)
        {
            throw new NotImplementedException();
        }
    }

    internal class FilterGreaterOrEqual : LDAPFilter
    {
        public string Attribute { get; internal set; }
        public Memory<byte> Value { get; internal set; }

        public FilterGreaterOrEqual(string attribute, Memory<byte> value)
        {
            Attribute = attribute;
            Value = value;
        }

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 5, true));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute));
            writer.WriteOctetString(Value.Span);
        }
    }

    internal class FilterLessOrEqual : LDAPFilter
    {
        public string Attribute { get; internal set; }
        public Memory<byte> Value { get; internal set; }

        public FilterLessOrEqual(string attribute, Memory<byte> value)
        {
            Attribute = attribute;
            Value = value;
        }

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 6, true));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute));
            writer.WriteOctetString(Value.Span);
        }
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

    internal class FilterApproxMatch : LDAPFilter
    {
        public string Attribute { get; internal set; }
        public Memory<byte> Value { get; internal set; }

        public FilterApproxMatch(string attribute, Memory<byte> value)
        {
            Attribute = attribute;
            Value = value;
        }

        public override void ToBytes(AsnWriter writer)
        {
            using AsnWriter.Scope _ = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 8, true));
            writer.WriteOctetString(Encoding.UTF8.GetBytes(Attribute));
            writer.WriteOctetString(Value.Span);
        }
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
