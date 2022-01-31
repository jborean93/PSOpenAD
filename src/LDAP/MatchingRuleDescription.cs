using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>Definition of a matching rule.</summary>
/// <remarks>
/// <para>
/// The ABNF notation of a MatchingRuleDescription is:
///    MatchingRuleDescription = LPAREN WSP
///        numericoid                 ; object identifier
///        [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
///        [ SP "DESC" SP qdstring ]  ; description
///        [ SP "OBSOLETE" ]          ; not active
///        SP "SYNTAX" SP numericoid  ; assertion syntax
///         extensions WSP RPAREN      ; extensions
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.3">RFC 4512 4.1.3. Matching Rules</see>
public class MatchingRuleDescription : LdapAbnfClass
{
    /// <summary>The object identifier assigned to this matching rule.</summary>
    public string OID { get; set; } = "";

    /// <summary>Short names (descriptors) identifying this matching rule.</summary>
    public string[] Names { get; set; } = Array.Empty<string>();

    /// <summary>The short descriptive string.</summary>
    public string? Description { get; set; }

    /// <summary>Indicates this matching rule is not active.</summary>
    public bool Obsolete { get; set; }

    /// <summary>Identifies the assertion syntax by object identifier.</summary>
    public string Syntax { get; set; } = "";

    internal override List<(string, TryReadField, bool)> Fields => new()
    {
        ("OID", TryReadIdentifierField, true),
        ("NAME", TryReadNameField, false),
        ("DESC", TryReadDescField, false),
        ("OBSOLETE", TryReadObsoleteField, false),
        ("SYNTAX", TryReadSyntaxField, true),
    };

    public MatchingRuleDescription(string definition) : base(definition) { }

    public override string ToString()
    {
        StringBuilder sb = new();
        sb.AppendFormat("( {0}", OID);

        if (Names.Length > 0)
        {
            string names = AbnfEncoder.EncodeQDescrs(Names);
            sb.AppendFormat(" NAME {0}", names);
        }

        if (!string.IsNullOrWhiteSpace(Description))
        {
            string desc = AbnfEncoder.EncodeQDString(Description);
            sb.AppendFormat(" DESC {0}", desc);
        }

        if (Obsolete)
        {
            sb.Append(" OBSOLETE");
        }

        sb.AppendFormat(" SYNTAX {0}", Syntax);

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

    private bool TryReadNameField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadQDescrs(data, out var value, out charConsumed))
        {
            Names = value;
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

    private bool TryReadObsoleteField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        Obsolete = true;
        return true;
    }

    private bool TryReadSyntaxField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadNumericOid(data, true, out var oid, out charConsumed))
        {
            Syntax = oid;
            return true;
        }
        else
        {
            return false;
        }
    }
}
