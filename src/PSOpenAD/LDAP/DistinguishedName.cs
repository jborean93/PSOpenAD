using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;

namespace PSOpenAD.LDAP;

public class AttributeTypeAndValue
{
    /// Stores the original parsed value (if provided) for the ToString() impl
    private readonly string? _original;

    /// <summary>
    /// The attribute type
    /// </summary>
    public string Type { get; }

    /// <summary>
    /// The literal string representation of the value.
    /// </summary>
    public string Value { get; }

    /// <summary>
    /// The raw value as an string where necessary characters are escaped.
    /// </summary>
    public string EscapedValue => IsASN1EncodedValue ? Value : EscapeAttributeValue(Value);

    /// <summary>
    /// Is true when Value is the ASN.1 encoded value '#{hexpairs}' and not the
    /// literal string value.
    /// </summary>
    public bool IsASN1EncodedValue { get; }

    /// <summary>
    /// Creates a new AttributeTypeAndValue instance from the provided values.
    /// </summary>
    /// <param name="type">The attribute type</param>
    /// <param name="value">The attribute value</param>
    /// <remarks>
    /// The provided value is treated literally and should not be escaped.
    /// The EscapedValue property can provide an escaped string from that
    /// value or the ToString() method can provide the full ATV string
    /// representation.
    /// </remarks>
    public AttributeTypeAndValue(string type, string value)
        : this(type, value, false, null)
    { }

    /// <summary>
    /// Creates a new AttributeTypeAndValue instance with an ASN.1 BER encoded
    /// value.
    /// </summary>
    /// <param name="type"The attribute type></param>
    /// <param name="value">The ASN.1 BER encoded byte[] value.</param>
    /// <remarks>
    /// This constructor will set IsASN1EncodedValue and stores the raw ASN.1
    /// BER encoded values as the already escaped string under Value.
    /// </remarks>
    public AttributeTypeAndValue(string type, byte[] value)
        : this(type, $"#{Convert.ToHexString(value)}", true, null)
    { }

    private AttributeTypeAndValue(
        string type,
        string value,
        bool isRawAsn1Value,
        string? original)
    {
        _original = original;
        Type = type;
        Value = value;
        IsASN1EncodedValue = isRawAsn1Value;
    }

    /// <summary>
    /// Escapes a raw string value that can be used as the attribute value of
    /// a distinguished name. This implementation will escape the characters
    /// needed with a backslash.
    /// </summary>
    /// <param name="value">The attribute value to escape.</param>
    /// <returns>The escaped attribute value string.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc2253#section-2.4">RFC 2253 2.4. Converting an AttributeValue from ASN.1 to a String</see>
    public static string EscapeAttributeValue(ReadOnlySpan<char> value)
    {
        int escapedLength = value.Length;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (ShouldEscapeChar(c, start: i == 0, end: i == value.Length - 1))
            {
                escapedLength++;
            }
            else if (ShouldHexEscapeChar(c))
            {
                escapedLength += 2;
            }
        }

        unsafe
        {
            fixed (char* valuePtr = value)
            {
                return string.Create(
                    escapedLength,
                    ((nint)valuePtr, value.Length),
                    static (span, state) =>
                    {
                        (nint ptr, int length) = state;
                        ReadOnlySpan<char> value = new((void*)ptr, length);
                        for (int i = 0, j = 0; i < value.Length; i++)
                        {
                            char c = value[i];
                            if (ShouldEscapeChar(c, start: i == 0, end: i == value.Length - 1))
                            {
                                span[j++] = '\\';
                                span[j++] = c;
                            }
                            else if (ShouldHexEscapeChar(c))
                            {
                                string hex = ((short)c).ToString("X2");
                                span[j++] = '\\';
                                span[j++] = hex[0];
                                span[j++] = hex[1];
                            }
                            else
                            {
                                span[j++] = c;
                            }
                        }
                    });
            }
        }
    }

    /// <summary>Tries to parse a attributeTypeAndValue value.</summary>
    /// <remarks>
    /// ABNF notation for attributeTypeAndValue is:
    ///     attributeTypeAndValue = attributeType EQUALS attributeValue
    ///     attributeType = descr / numericoid
    ///     attributeValue = string / hexstring
    ///
    ///     descr = keystring
    ///     hexstring = SHARP 1*hexpair
    ///     hexpair = HEX HEX
    /// </remarks>
    /// <param name="data">The input data to parse from.</param>
    /// <param name="result">The AttributeTypeValue result if successful.</param>
    /// <param name="consumed">
    /// Number of chars consumed in the input data, this is undefined if the
    /// parsing had failed.
    /// </param>
    /// <returns><c>true</c> if <c>value</c> was successfully parsed.</returns>
    /// <see href=""></see>
    internal static bool TryParse(
        ReadOnlySpan<char> data,
        [NotNullWhen(true)] out AttributeTypeAndValue? result,
        out int consumed)
    {
        result = null;

        // While not in the spec many implementations allow whitespace between
        // each RDN member so this replicates that behaviour.
        int startIdx = CountStartWhitespace(data);
        ReadOnlySpan<char> buffer = data[startIdx..];
        consumed = startIdx;

        // Parse the attributeType and check the next char is =
        if (
        !(
            AbnfDecoder.TryParseNumericOid(buffer, out var attrType, out var read) ||
            AbnfDecoder.TryParseKeyString(buffer, out attrType, out read))
        )
        {
            return false;
        }

        buffer = buffer[read..];
        consumed += read;

        read = CountStartWhitespace(buffer);
        buffer = buffer[read..];
        consumed += read;

        if (buffer.Length == 0 || buffer[0] != '=')
        {
            return false;
        }
        buffer = buffer[1..];
        consumed += 1;

        read = CountStartWhitespace(buffer);
        buffer = buffer[read..];
        consumed += read;

        // Parse the attributeValue which is either in the string or hexstring
        // form.
        bool isRawAsn1Value = false;
        if (TryParseHexString(buffer, out var value, out read))
        {
            isRawAsn1Value = true;
        }
        else if (!TryParseValueString(buffer, out value, out read))
        {
            return false;
        }

        buffer = buffer[read..];
        consumed += read;
        string originalValue = data[startIdx..consumed].ToString();

        read = CountStartWhitespace(buffer);
        consumed += read;

        result = new(attrType, value, isRawAsn1Value, originalValue);
        return true;
    }

    private static bool TryParseHexString(
        ReadOnlySpan<char> data,
        [NotNullWhen(true)] out string? value,
        out int consumed)
    {
        value = null;
        consumed = 0;

        // A hexstring starts with # and must contain at least 1 hexpair.
        if (data.Length < 3 || data[0] != '#')
        {
            return false;
        }

        int hexLength = 1;
        ReadOnlySpan<char> buffer = data[1..];
        while (buffer.Length > 1 && AbnfDecoder.IsHex(buffer[0]) && AbnfDecoder.IsHex(buffer[1]))
        {
            buffer = buffer[2..];
            hexLength += 2;
        }

        // The value must be the end of the string or an RDN separator.
        int whitespaceRead = CountStartWhitespace(buffer);
        buffer = buffer[whitespaceRead..];
        if (buffer.Length > 0 && buffer[0] != ',' && buffer[0] != '+')
        {
            return false;
        }

        value = data[..hexLength].ToString();
        consumed += hexLength;
        return true;
    }

    private static bool TryParseValueString(
        ReadOnlySpan<char> data,
        [NotNullWhen(true)] out string? value,
        out int consumed)
    {
        value = null;
        consumed = 0;

        // We won't know the final byte count until after we process the
        // value but it will not exceed the byte count of the input data.
        using var pool = MemoryPool<byte>.Shared.Rent(Encoding.UTF8.GetByteCount(data));
        Span<byte> byteBuffer = pool.Memory.Span;
        int bytesConsumed = 0;

        // Keep track of a buffer to encode only when an escape char is found.
        ReadOnlySpan<char> charBuffer = data;
        int charsConsumed = 0;
        int spaceCount = 0;
        bool isStart = true;

        while (data.Length > 0)
        {
            char c = data[0];
            data = data[1..];
            consumed++;
            charsConsumed++;

            // A trailing character must not end in a space, this keeps track
            // of how many spaces (if any) to discard at the end. This is
            // reset back to 0 when encounting a valid char.
            if (c == ' ')
            {
                spaceCount++;
            }
            else if (c == '\\')
            {
                // Encode everything found so far into the byte buffer plus set
                // the escaped byte.
                if (charsConsumed > 1)
                {
                    int encodedBytes = Encoding.UTF8.GetBytes(
                        charBuffer[..(charsConsumed - 1)],
                        byteBuffer[bytesConsumed..]);
                    bytesConsumed += encodedBytes;
                }

                if (data.Length > 0 && (data[0] == '\\' || IsEscapableCharSpecial(data[0])))
                {
                    byteBuffer[bytesConsumed] = (byte)data[0];
                    bytesConsumed++;

                    data = data[1..];
                    consumed++;
                }
                else if (data.Length > 1 && AbnfDecoder.IsHex(data[0]) && AbnfDecoder.IsHex(data[1]))
                {
                    byteBuffer[bytesConsumed] = Convert.ToByte(data[..2].ToString(), 16);
                    bytesConsumed++;

                    data = data[2..];
                    consumed += 2;
                }
                else
                {
                    return false;
                }

                charBuffer = data;
                charsConsumed = 0;
                spaceCount = 0;
                spaceCount = 0;
            }
            else if (c == ',' || c == '+')
            {
                // used to delineate another RDN or attribute in the same RDN.
                charsConsumed--;
                consumed--;
                break;
            }
            else if (c == '\0' || IsEscapableCharEscaped(c) || (isStart && c == '#'))
            {
                // These chars cannot be present unless prefixed by \.
                return false;
            }
            else
            {
                spaceCount = 0;
            }

            isStart = false;
        }

        // Remove any trailing spaces which we don't want in the final value.
        charsConsumed -= spaceCount;
        consumed -= spaceCount;  // The whitespace is trimmed in parent func.
        if (charsConsumed > 0)
        {
            int encodedBytes = Encoding.UTF8.GetBytes(
                charBuffer[..charsConsumed],
                byteBuffer[bytesConsumed..]);
            bytesConsumed += encodedBytes;
        }

        if (bytesConsumed == 0)
        {
            return false;
        }

        value = Encoding.UTF8.GetString(byteBuffer[..bytesConsumed]);
        return true;
    }

    internal static int CountStartWhitespace(ReadOnlySpan<char> data)
    {
        int consumed = 0;
        while (data.Length > 0 && data[0] == ' ')
        {
            data = data[1..];
            consumed++;
        }
        return consumed;
    }

    // https://datatracker.ietf.org/doc/html/rfc4514#section-3 - special
    private static bool IsEscapableCharSpecial(char c)
        => IsEscapableCharEscaped(c) || c == ' ' || c == '#' || c == '=';

    // https://datatracker.ietf.org/doc/html/rfc4514#section-3 - escaped
    private static bool IsEscapableCharEscaped(char c)
        => c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>';

    // https://datatracker.ietf.org/doc/html/rfc4514#section-2.4
    private static bool ShouldEscapeChar(char c, bool start = false, bool end = false)
    {
        if (start && (c == ' ' || c == '#'))
        {
            return true;
        }
        else if (end && c == ' ')
        {
            return true;
        }

        return IsEscapableCharEscaped(c) || c == '\\';
    }

    // Active Directory also needs to escape these 4 chars that aren't part of the RFC.
    // They are escaped using \ and the hex representation rather than just \ by itself.
    // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names
    private static bool ShouldHexEscapeChar(char c)
        => c == '\0' || c == '\n' || c == '\r' || c == '=' || c == '/';

    public override string ToString()
        => _original ?? $"{Type}={EscapedValue}";
}

public class RelativeDistinguishedName
{
    private readonly string? _original;
    public AttributeTypeAndValue[] Values { get; }

    public RelativeDistinguishedName(AttributeTypeAndValue[] values)
        : this(values, null)
    { }

    private RelativeDistinguishedName(AttributeTypeAndValue[] values, string? original)
    {
        Values = values;
        _original = original;
    }

    internal static bool TryParse(
        ReadOnlySpan<char> value,
        [NotNullWhen(true)] out RelativeDistinguishedName? result,
        out int consumed)
    {
        result = null;
        consumed = AttributeTypeAndValue.CountStartWhitespace(value);
        ReadOnlySpan<char> buffer = value = value[consumed..];

        List<AttributeTypeAndValue> values = new();
        int remainingSpaces;
        while (true)
        {
            if (!AttributeTypeAndValue.TryParse(buffer, out var atv, out int atvConsumed))
            {
                return false;
            }

            values.Add(atv);
            buffer = buffer[atvConsumed..];
            consumed += atvConsumed;

            if (buffer.Length == 0 || buffer[0] == ',')
            {
                remainingSpaces = atvConsumed - atv.ToString().Length;
                break;
            }

            buffer = buffer[1..];
            consumed++;
        }

        result = new(values.ToArray(), value[..(consumed - remainingSpaces)].ToString());
        return true;
    }

    public override string ToString()
        => _original ?? string.Join("+", Values.Select(v => v.ToString()));
}

public class DistinguishedName
{
    private readonly string? _original;

    /// <summary>
    /// The RelativeDistinguishedNames of the DN. Each entry contains at least
    /// 1 AttributeTypeAndValue.
    /// </summary>
    public RelativeDistinguishedName[] RelativeNames { get; }

    public DistinguishedName(RelativeDistinguishedName[] rdns)
        : this(rdns, null)
    { }

    private DistinguishedName(RelativeDistinguishedName[] rdns, string? original)
    {
        RelativeNames = rdns;
        _original = original;
    }

    internal static DistinguishedName Parse(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn))
        {
            return new(Array.Empty<RelativeDistinguishedName>(), "");
        }

        ReadOnlySpan<char> value = dn;
        List<RelativeDistinguishedName> rdns = new();
        while (value.Length > 0)
        {
            if (!RelativeDistinguishedName.TryParse(value, out var rdn, out var consumed))
            {
                string msg = $"The input string '{dn}' was not a valid DistinguishedName";
                throw new ArgumentException(msg, nameof(dn));
            }

            rdns.Add(rdn);
            value = value[consumed..];

            if (value.Length > 0)
            {
                value = value[1..];
            }
        }

        return new(rdns.ToArray(), dn);
    }

    public override string ToString()
        => _original ?? string.Join(",", RelativeNames.Select(r => r.ToString()));

    // Here for backwards compatibility.
    public static string EscapeAttributeValue(ReadOnlySpan<char> value)
        => AttributeTypeAndValue.EscapeAttributeValue(value);
}
