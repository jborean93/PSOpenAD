using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>A Teletex Terminal Identifier.</summary>
/// <remarks>
/// <para>
/// The ABNF notation of this field is:
///     teletex-id = ttx-term *(DOLLAR ttx-param)
///     ttx-term   = PrintableString          ; terminal identifier
///     ttx-param  = ttx-key COLON ttx-value  ; parameter
///     ttx-key    = "graphic" / "control" / "misc" / "page" / "private"
///     ttx-value  = *ttx-value-octet
///
///     ttx-value-octet = %x00-23
///                     / (%x5C "24")  ; escaped "$"
///                     / %x25-5B
///                     / (%x5C "5C")  ; escaped "\"
///                     / %x5D-FF
/// </para>
/// <para>
/// The LDAP definition for this syntax is:
///     ( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )
/// </para>
/// </remarks>
public class TeletexTerminalIdentifier
{
    /// <summary>Teletex Terminal Identifier.</summary>
    public string Identifier { get; }

    /// <summary>Array of optional parameters for the identifier.</summary>
    public TeletexTerminalParameter[] Parameters { get; }

    public TeletexTerminalIdentifier(ReadOnlySpan<byte> data)
    {
        int dollarIdx = data.IndexOf((byte)0x24); // $
        List<TeletexTerminalParameter> parameters = new();

        if (dollarIdx == -1)
        {
            Identifier = Encoding.ASCII.GetString(data);
        }
        else
        {
            Identifier = Encoding.ASCII.GetString(data[..dollarIdx]);
            data = data[(dollarIdx + 1)..];

            while (data.Length > 0)
            {
                parameters.Add(TeletexTerminalParameter.ParseParameter(data, out var read));
                data = data[read..];
            }
        }

        Parameters = parameters.ToArray();
    }
}

/// <summary>Encoded form of a Teletex Terminal Identifier parameter.</summary>
public class TeletexTerminalParameter
{
    /// <summary>The name/key of the parameter.</summary>
    public string Name { get; }

    /// <summary>The raw bytes of the parameter.</summary>
    public byte[] Value { get; }

    public TeletexTerminalParameter(string name, byte[] value)
    {
        Name = name;
        Value = value;
    }

    /// <summary>Parse a Teletex Terminal Identifier parameter from the raw bytes.</summary>
    /// <param name="data">The raw bytes to start parsing from.</param>
    /// <oaram name="read">How many bytes that were consumed for this parameter.</param>
    /// <returns>The parsed Teletex Terminal Identifier parameter.</returns>
    internal static TeletexTerminalParameter ParseParameter(ReadOnlySpan<byte> data, out int read)
    {
        int colonIdx = data.IndexOf((byte)0x3A); // :
        string name = Encoding.ASCII.GetString(data[..colonIdx]);

        // The serialized form is going to be the same size or larger (if $ or \ are escaped). Keep the count to know
        // how much data was written after it was converted from the escaped form.
        Memory<byte> value = new(new byte[data.Length - colonIdx]);
        Span<byte> encodedValue = value.Span;
        int count = 0;

        for (read = colonIdx + 1; read < data.Length; read++)
        {
            char c = (char)data[read];

            // Need to escape \24 or \5C is found.
            if (c == '\\' && data.Length > (read + 2))
            {
                string escapedHex = Encoding.ASCII.GetString(data.Slice(read + 1, 2));
                encodedValue[count] = Convert.ToByte(escapedHex, 16);
                count++;
                read += 2;
                continue;
            }
            else if (c == '$')
            {
                // Include the $ so the next call starts with what comes after $
                read++;
                break;
            }

            encodedValue[count] = data[read];
            count++;
        }

        return new TeletexTerminalParameter(name, value[..count].ToArray());
    }
}
