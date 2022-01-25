using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>Definition of an LDAP Syntax.</summary>
/// <remarks>
/// <para>
/// The ABNF notation of a SyntaxDescription is:
///     SyntaxDescription = LPAREN WSP
///         numericoid                 ; object identifier
///         [ SP "DESC" SP qdstring ]  ; description
///         extensions WSP RPAREN      ; extensions
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.5">RFC 4512 4.1.5. LDAP Syntaxes</see>
public class SyntaxDescription : LdapAbnfClass
{
    /// <summary>The object identifier assigned to this LDAP syntax.</summary>
    public string OID { get; set; } = "";

    /// <summary>The short descriptive string.</summary>
    public string? Description { get; set; }

    internal override List<(string, TryReadField, bool)> Fields => new()
    {
        ("OID", TryReadIdentifierField, true),
        ("DESC", TryReadDescField, false),
    };

    public SyntaxDescription(string definition) : base(definition) { }

    public override string ToString()
    {
        StringBuilder sb = new();
        sb.AppendFormat("( {0}", OID);

        if (!string.IsNullOrWhiteSpace(Description))
        {
            string desc = AbnfEncoder.EncodeQDString(Description);
            sb.AppendFormat(" DESC {0}", desc);
        }

        foreach (KeyValuePair<string, string[]> ext in Extensions)
        {
            string value = AbnfEncoder.EncodeQDStrings(ext.Value);
            sb.AppendFormat(" {0} {1}", ext.Key, value);
        }

        sb.Append(" )");
        return sb.ToString();
    }

    private bool TryReadIdentifierField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadNumericOid(data, false, out var oid, out charConsumed))
        {
            OID = oid;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadDescField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadQDString(data, out var value, out charConsumed))
        {
            Description = value;
            return true;
        }
        else
        {
            return false;
        }
    }
}
