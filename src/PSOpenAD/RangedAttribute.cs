using System;
using System.Globalization;

namespace PSOpenAD;

/// <summary>
/// Parses and builds the LDAP ranged-retrieval attribute option Active Directory uses
/// when a multivalued attribute exceeds MaxValRange. A response names the attribute
/// "member;range=0-1499" rather than "member", and the final page ends in "*".
/// </summary>
/// <see href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e27b48db-6f82-44cd-9038-2e54f790cc1f">3.1.1.3.1.3.3 Range Retrieval of Attribute Values</see>
internal static class RangedAttribute
{
    private const string RangeOption = ";range=";

    /// <summary>Returns true when name carries a range option, and decomposes it.</summary>
    /// <param name="high">The inclusive upper bound, or -1 when the page is the last.</param>
    /// <param name="isFinal">True when the range ends in "*", meaning no further pages.</param>
    public static bool TryParse(string name, out string baseName, out int low, out int high, out bool isFinal)
    {
        baseName = name;
        low = 0;
        high = -1;
        isFinal = false;

        int idx = name.IndexOf(RangeOption, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
        {
            return false;
        }

        baseName = name[..idx];
        string range = name[(idx + RangeOption.Length)..];

        int dash = range.IndexOf('-');
        if (dash < 0)
        {
            baseName = name;
            return false;
        }

        if (!int.TryParse(range[..dash], NumberStyles.None, CultureInfo.InvariantCulture, out low))
        {
            baseName = name;
            return false;
        }

        string upper = range[(dash + 1)..];
        if (upper == "*")
        {
            isFinal = true;
            high = -1;
            return true;
        }

        if (!int.TryParse(upper, NumberStyles.None, CultureInfo.InvariantCulture, out high))
        {
            baseName = name;
            return false;
        }

        return true;
    }

    /// <summary>Builds the attribute name requesting everything after the page ending at high.</summary>
    public static string NextRequest(string baseName, int high)
        => $"{baseName}{RangeOption}{high + 1}-*";

    /// <summary>
    /// Returns the plain attribute name backing a possibly-ranged one: TryParse's baseName
    /// when name carries a range option, otherwise name unchanged. A ranged wire name (e.g.
    /// "member;range=0-1") must be treated as identical to its plain counterpart wherever
    /// the attribute is being reasoned about rather than requested on the wire - schema
    /// validation, and projecting the name an output property is surfaced under - since the
    /// entry itself is always renamed back to the plain name before the object is built.
    /// </summary>
    public static string PlainName(string name)
        => TryParse(name, out string baseName, out _, out _, out _) ? baseName : name;
}
