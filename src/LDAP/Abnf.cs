using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

internal static class LdapAbnfDefinitions
{
    /// <summary>Checks whether the current char is an ALPHA char.</summary>
    /// <remarks>
    /// ABNF notation for ALPHA is:
    ///     ALPHA   = %x41-5A / %x61-7A   ; "A"-"Z" / "a"-"z"
    /// </remarks>
    /// <param name="c">The character to check</param>
    /// <returns>Whether the character is an ALPHA char or not.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool IsAlpha(char c) => (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A);

    /// <summary>Checks whether the current char is a DIGIT char.</summary>
    /// <remarks>
    /// ABNF notation for DIGIT is:
    ///     DIGIT   = %x30 / LDIGIT       ; "0"-"9"
    /// </remarks>
    /// <param name="c">The character to check</param>
    /// <returns>Whether the character is an DIGIT char or not.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool IsDigit(char c) => c == 0x30 || IsLDigit(c);

    /// <summary>Checks whether the current char is a LDIGIT char.</summary>
    /// <remarks>
    /// ABNF notation for LDIGIT is:
    ///     LDIGIT  = %x31-39             ; "1"-"9"
    /// </remarks>
    /// <param name="c">The character to check</param>
    /// <returns>Whether the character is an LDIGIT char or not.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool IsLDigit(char c) => c >= 0x31 && c <= 0x39;

    /// <summary>Checks whether the current char is a HEX char.</summary>
    /// <remarks>
    /// ABNF notation for HEX is:
    ///     HEX     = DIGIT / %x41-46 / %x61-66 ; "0"-"9" / "A"-"F" / "a"-"f"
    /// </remarks>
    /// <param name="c">The character to check</param>
    /// <returns>Whether the character is an HEX char or not.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool IsHex(char c) => IsDigit(c) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);

    /// <summary>Checks whether the current char is a QUTF1 char.</summary>
    /// <remarks>
    /// ABNF notation for QUTF1 is:
    ///     ; Any ASCII character except %x27 ("'") and %x5C ("\")
    ///     QUTF1    = %x00-26 / %x28-5B / %x5D-7F
    /// </remarks>
    /// <param name="c">The character to check</param>
    /// <returns>Whether the character is an QUTF1 char or not.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool IsQUTF1(char c)
        => (c >= 0x00 && c <= 0x26) || (c >= 0x28 && c <= 0x5B) || (c >= 0x5D && c <= 0x7F);

    /// <summary>Tries to parse an SP value.</summary>
    /// <remarks>
    /// ABNF notation for SP is:
    ///     SP      = 1*SPACE  ; one or more " "
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="sp">The sp value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the sp value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool TryParseSP(ReadOnlySpan<char> data, out string sp, out int charsConsumed)
    {
        TryParseWSP(data, out sp, out charsConsumed);

        return charsConsumed > 0;
    }

    /// <summary>Tries to parse a WSP value.</summary>
    /// <remarks>
    /// ABNF notation for WSP is:
    ///     WSP     = 0*SPACE  ; zero or more " "
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="wsp">The wsp value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the wsp value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool TryParseWSP(ReadOnlySpan<char> data, out string wsp, out int charsConsumed)
    {
        for (charsConsumed = 0; charsConsumed < data.Length; charsConsumed++)
        {
            if (data[charsConsumed] != ' ')
            {
                break;
            }
        }

        wsp = data[..charsConsumed].ToString();
        return true;
    }

    /// <summary>Tries to parse a keystring value.</summary>
    /// <remarks>
    /// ABNF notation for keystring is:
    ///     keystring = leadkeychar *keychar
    ///     leadkeychar = ALPHA
    ///     keychar = ALPHA / DIGIT / HYPHEN
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="keystring">The keystring value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the keystring value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool TryParseKeyString(ReadOnlySpan<char> data, out string keystring, out int charsConsumed)
    {
        if (data.Length < 1 || !IsAlpha(data[0]))
        {
            keystring = "";
            charsConsumed = 0;
            return false;
        }

        for (charsConsumed = 1; charsConsumed < data.Length; charsConsumed++)
        {
            char c = data[charsConsumed];

            if (!(IsAlpha(c) || IsDigit(c) || c == '-'))
            {
                break;
            }
        }

        if (charsConsumed > 0)
        {
            keystring = data[..charsConsumed].ToString();
            return true;
        }
        else
        {
            keystring = "";
            charsConsumed = 0;
            return false;
        }
    }

    /// <summary>Tries to parse an escaped UTF-8 string.</summary>
    /// <remarks>
    /// <para>
    /// ABNF notation for an escaped UTF-8 isn't defined as a single value but is represented as:
    ///     QS / QQ / QUTF8     ; escaped UTF-8 string
    ///     QQ =  ESC %x32 %x37 ; "\27"
    ///     QS =  ESC %x35 ( %x43 / %x63 ) ; "\5C" / "\5c"
    ///     QUTF8    = QUTF1 / UTFMB
    ///     QUTF1    = %x00-26 / %x28-5B / %x5D-7F
    ///     UTFMB   = UTF2 / UTF3 / UTF4
    ///     UTF2    = %xC2-DF UTF0
    ///     UTF3    = %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
    ///             %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
    ///     UTF4    = %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
    ///             %xF4 %x80-8F 2(UTF0)
    /// </para>
    /// <para>
    /// Essentially an escaped UTF-8 string is a UTF-8 string but with ' escaped as \27 and \ escaped as \5c.
    /// </para>
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="utf8String">The escaped UTF-8 value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the escaped UTF-8 value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool TryParseEscapedUTF8String(ReadOnlySpan<char> data, out string utf8String, out int charsConsumed)
    {
        StringBuilder sb = new(data.Length);
        for (charsConsumed = 0; charsConsumed < data.Length; charsConsumed++)
        {
            char c = data[charsConsumed];

            if (c == '\\')
            {
                // If the char is \ check if it contains 2 more escaped digits for \ or ' otherwise treat this as the
                // end of the escaped UTF8 string.
                if (charsConsumed < data.Length - 2)
                {
                    string escapedHex = data.Slice(charsConsumed + 1, 2).ToString();
                    if (escapedHex == "27")
                    {
                        sb.Append('\'');
                        charsConsumed += 2;
                        continue;
                    }
                    else if (escapedHex == "5c" || escapedHex == "5C")
                    {
                        sb.Append('\\');
                        charsConsumed += 2;
                        continue;
                    }
                }

                break;
            }
            else if (c == '\'')
            {
                break;
            }

            sb.Append(c);
        }

        if (charsConsumed > 0)
        {
            utf8String = sb.ToString();
            return true;
        }
        else
        {
            utf8String = "";
            return false;
        }
    }

    /// <summary>Tries to parse a number value.</summary>
    /// <remarks>
    /// ABNF notation for number is:
    ///     number  = DIGIT / ( LDIGIT 1*DIGIT )
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="number">The number value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the number value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool TryParseNumber(ReadOnlySpan<char> data, out string number, out int charsConsumed)
    {
        for (charsConsumed = 0; charsConsumed < data.Length; charsConsumed++)
        {
            char c = data[charsConsumed];

            // Scan until a non-digit or only the first if it was 0.
            if (!IsDigit(c) || (charsConsumed == 1 && !IsLDigit(data[0])))
            {
                break;
            }
        }

        if (charsConsumed > 0)
        {
            number = data[..charsConsumed].ToString();
            return true;
        }
        else
        {
            number = "";
            charsConsumed = 0;
            return false;
        }
    }

    /// <summary>Tries to parse a numericoid value.</summary>
    /// <remarks>
    /// ABNF notation for numericoid is:
    ///     numericoid = number 1*( DOT number )
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="numericoid">The numericoid value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the numericoid value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool TryParseNumericOid(ReadOnlySpan<char> data, out string numericoid, out int charsConsumed)
    {
        int parts = 0;
        charsConsumed = 0;
        while (charsConsumed < data.Length)
        {
            char c = data[charsConsumed];

            int numberLength = 0;
            if (parts == 0)
            {
                if (!TryParseNumber(data[charsConsumed..], out var _, out numberLength))
                {
                    break;
                }
            }
            else if (c == '.' && parts > 0)
            {
                if (TryParseNumber(data[(charsConsumed + 1)..], out var _, out numberLength))
                {
                    numberLength++; // Include the . in the length if it was a number
                }
                else
                {
                    break;
                }
            }
            else
            {
                break;
            }

            charsConsumed += numberLength;
            parts++;
        }

        if (parts < 2)
        {
            // A numeric OID must have at least 2 components to be valid.
            numericoid = "";
            charsConsumed = 0;
            return false;
        }
        else
        {
            numericoid = data[..charsConsumed].ToString();
            return true;
        }
    }

    /// <summary>Tries to parse an oid value.</summary>
    /// <remarks>
    /// ABNF notation for oid is:
    ///     oid = descr / numericoid
    ///     descr = keystring
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="oid">The oid value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the oid value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-1.4">RFC 4512 1.4. Common ABNF Productions</see>
    public static bool TryParseOid(ReadOnlySpan<char> data, out string oid, out int charsConsumed)
    {
        return TryParseKeyString(data, out oid, out charsConsumed) ||
            TryParseNumericOid(data, out oid, out charsConsumed);
    }

    /// <summary>Tries to parse a noidlen value.</summary>
    /// <remarks>
    /// ABNF notation for noidlen is:
    ///     noidlen = numericoid [ LCURLY len RCURLY ]
    ///     len = number
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="oid">The oid part of the value if the input data was in a valid format.</param>
    /// <param name="len">The len part of the value if set and the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the noidlen values.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool TryParseNOidLen(ReadOnlySpan<char> data, out string oid, out string? len, out int charsConsumed)
    {
        if (TryParseNumericOid(data, out oid, out charsConsumed))
        {
            data = data[charsConsumed..];
            len = null;

            if (data.Length > 2 && data[0] == '{' &&
                TryParseNumber(data[1..], out var oidLen, out var lenConsumed) &&
                data.Length > lenConsumed + 1 && data[lenConsumed + 1] == '}')
            {
                len = oidLen;
                charsConsumed += lenConsumed + 2;
            }

            return true;
        }

        oid = "";
        len = null;
        return false;
    }

    /// <summary>Tries to parse a qdescrs value.</summary>
    /// <remarks>
    /// ABNF notation for qdescrs is:
    ///     qdescrs = qdescr / ( LPAREN WSP qdescrlist WSP RPAREN )
    ///     qdescrlist = [ qdescr *( SP qdescr ) ]
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="qdescrs">The qdescrs values if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the qdescrs values.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool TryParseQDescrs(ReadOnlySpan<char> data, out string[] qdescrs, out int charsConsumed)
    {
        return TryParseQuotedStringList(data, out qdescrs, out charsConsumed, TryParseQDescr);
    }

    /// <summary>Tries to parse a qdescr value.</summary>
    /// <remarks>
    /// ABNF notation for qdescr is:
    ///     qdescr = SQUOTE descr SQUOTE
    ///     descr = keystring
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="qdescr">The qdescr value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the qdescr value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool TryParseQDescr(ReadOnlySpan<char> data, out string qdescr, out int charsConsumed)
    {
        if (data.Length > 3 && data[0] == '\'')
        {
            // Check if the value after the single quote is a keystring and the immediate value after that is another
            // single quote.
            bool isKeystring = TryParseKeyString(data[1..], out qdescr, out charsConsumed);
            if (isKeystring && data.Length >= 2 + charsConsumed && data[charsConsumed + 1] == '\'')
            {
                charsConsumed += 2;
                return true;
            }
        }

        qdescr = "";
        charsConsumed = 0;
        return false;
    }

    /// <summary>Tries to parse a qdstrings value.</summary>
    /// <remarks>
    /// ABNF notation for qdstrings is:
    ///     qdstrings = qdstring / ( LPAREN WSP qdstringlist WSP RPAREN )
    ///     qdstringlist = [ qdstring *( SP qdstring ) ]
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="qdstrings">The qdstrings values if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the qdstrings values.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool TryParseQDStrings(ReadOnlySpan<char> data, out string[] qdstrings, out int charsConsumed)
    {
        return TryParseQuotedStringList(data, out qdstrings, out charsConsumed, TryParseQDString);
    }

    /// <summary>Tries to parse a qdescr value.</summary>
    /// <remarks>
    /// ABNF notation for qdstring is:
    ///     qdstring = SQUOTE dstring SQUOTE
    ///     dstring = 1*( QS / QQ / QUTF8 )   ; escaped UTF-8 string
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="qdstring">The qdstring value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the qdstring value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool TryParseQDString(ReadOnlySpan<char> data, out string qdstring, out int charsConsumed)
    {
        if (data.Length > 3 && data[0] == '\'')
        {
            // Check if the value after the single quote is an escaped UTF-8 string and the immediate value after that
            // is another single quote.
            bool isEscapedUtf8String = TryParseEscapedUTF8String(data[1..], out qdstring, out charsConsumed);
            if (isEscapedUtf8String && data.Length >= 2 + charsConsumed && data[charsConsumed + 1] == '\'')
            {
                charsConsumed += 2;
                return true;
            }
        }

        qdstring = "";
        charsConsumed = 0;
        return false;
    }

    /// <summary>Tries to parse a set of optional extensions value.</summary>
    /// <remarks>
    /// ABNF notation for extensions is:
    ///     extensions = *( SP xstring SP qdstrings )
    ///     xstring = "X" HYPHEN 1*( ALPHA / HYPHEN / USCORE )
    /// </remarks>
    /// <param name="data">The value to parse.</param>
    /// <param name="extensions">The extensions value if the input data was in a valid format.</param>
    /// <param name="charsConsumed">The number of chars that formed the extensions value.</param>
    /// <returns><c>true</c> if <c>data</c> was successfully parsed, else <c>false</c>.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1">RFC 4512 4.1. Schema Definitions</see>
    public static bool TryParseExtensions(ReadOnlySpan<char> data, out Dictionary<string, string[]> extensions,
        out int charsConsumed)
    {
        extensions = new();
        charsConsumed = 0;

        while (TryParseSP(data, out var _, out var entryConsumed))
        {
            // xstring
            data = data[entryConsumed..];
            if (data.Length < 3 || data[0] != 'X' || data[1] != '-')
            {
                break;
            }
            data = data[2..];
            entryConsumed += 2;

            string? key = null;
            for (int i = 0; i < data.Length; i++)
            {
                char c = data[i];

                if (!(IsAlpha(c) || c == '-' || c == '_'))
                {
                    if (i > 0)
                    {
                        key = data[..i].ToString();
                    }
                    break;
                }
            }

            if (key == null)
            {
                break;
            }
            else
            {
                data = data[key.Length..];
                entryConsumed += key.Length;
                key = "X-" + key;
            }

            // SP
            if (TryParseSP(data, out _, out var spaceConsumed))
            {
                data = data[spaceConsumed..];
                entryConsumed += spaceConsumed;
            }
            else
            {
                break;
            }

            // qdstrings
            if (TryParseQDStrings(data, out var values, out var stringsConsumed))
            {
                data = data[stringsConsumed..];
                entryConsumed += stringsConsumed;
                extensions[key] = values;
            }
            else
            {
                break;
            }

            charsConsumed += entryConsumed;
        }

        return true;
    }

    private delegate bool TryParsedQuotedString(ReadOnlySpan<char> data, out string value,
        out int charsConsumed);

    private static bool TryParseQuotedStringList(ReadOnlySpan<char> data, out string[] strings, out int charsConsumed,
        TryParsedQuotedString valueParser)
    {
        if (valueParser(data, out var value, out charsConsumed))
        {
            strings = new[] { value };
            return true;
        }
        else if (data.Length > 1 && data[0] == '(')
        {
            charsConsumed = 1;
            TryParseWSP(data[1..], out var _, out var wspConsumed);
            charsConsumed += wspConsumed;

            List<string> values = new();
            while (true)
            {
                if (values.Count > 0)
                {
                    bool isSp = TryParseSP(data[charsConsumed..], out _, out var spConsumed);
                    if (!isSp)
                    {
                        break;
                    }
                    charsConsumed += spConsumed;
                }

                bool isQDescr = valueParser(data[charsConsumed..], out value, out var qdescrConsumed);
                if (!isQDescr)
                {
                    break;
                }

                values.Add(value);
                charsConsumed += qdescrConsumed;
            }

            if (values.Count > 0)
            {
                TryParseWSP(data[charsConsumed..], out var _, out wspConsumed);
                charsConsumed += wspConsumed;

                if (data.Length > charsConsumed && data[charsConsumed] == ')')
                {
                    charsConsumed++;
                    strings = values.ToArray();
                    return true;
                }
            }
        }

        strings = Array.Empty<string>();
        charsConsumed = 0;
        return false;
    }
}
