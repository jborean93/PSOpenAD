using System;

namespace PSOpenAD.LDAP;

public static class DistinguishedName
{
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
            if (IsEscapableChar(c, start: i == 0, end: i == value.Length - 1))
            {
                escapedLength++;
            }
            else if (IsEscapableCharAD(c))
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
                            if (IsEscapableChar(c, start: i == 0, end: i == value.Length - 1))
                            {
                                span[j++] = '\\';
                                span[j++] = c;
                            }
                            else if (IsEscapableCharAD(c))
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

    private static bool IsEscapableChar(char c, bool start = false, bool end = false)
    {
        if (start && (c == ' ' || c == '#'))
        {
            return true;
        }
        else if (end && c == ' ')
        {
            return true;
        }
        else if (c == ',' || c == '+' || c == '"' || c == '\\' || c == '<' || c == '>' || c == ';')
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    // Active Directory also needs to escape these 4 chars that aren't part of the RFC.
    // They are escaped using \ and the hex representation rather than just \ by itself.
    // https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names
    private static bool IsEscapableCharAD(char c)
        => c == '\n' || c == '\r' || c == '=' || c == '/';
}
