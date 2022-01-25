using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>Definition of an object class.</summary>
/// <remarks>
/// <para>
/// The ABNF notation of an DITContentRuleDescription is:
///     DITContentRuleDescription = LPAREN WSP
///         numericoid                 ; object identifier
///         [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
///         [ SP "DESC" SP qdstring ]  ; description
///         [ SP "OBSOLETE" ]          ; not active
///         [ SP "AUX" SP oids ]       ; auxiliary object classes
///         [ SP "MUST" SP oids ]      ; attribute types
///         [ SP "MAY" SP oids ]       ; attribute types
///         [ SP "NOT" SP oids ]       ; attribute types
///         extensions WSP RPAREN      ; extensions
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.6">RFC 4512 4.1.6. DIT Content Rules</see>
public class DITContentRuleDescription : LdapAbnfClass
{
    /// <summary>The object identifier assigned to this object class.</summary>
    public string OID { get; set; } = "";

    /// <summary>Short names (descriptors) identifying this DIT content rule.</summary>
    public string[] Names { get; set; } = Array.Empty<string>();

    /// <summary>The short descriptive string.</summary>
    public string? Description { get; set; }

    /// <summary>Indicates this DIT content rule is not active.</summary>
    public bool Obsolete { get; set; }

    /// <summary>Set of auxiliary object classes that entries ubject to this DIT content rule may belong to.</summary>
    public string[] Auxiliary { get; set; } = Array.Empty<string>();

    /// <summary>Set of required attribute types.</summary>
    public string[] Must { get; set; } = Array.Empty<string>();

    /// <summary>Set of allowed attribute types.</summary>
    public string[] May { get; set; } = Array.Empty<string>();

    /// <summary>Set of allowed attribute types.</summary>
    public string[] Not { get; set; } = Array.Empty<string>();

    internal override List<(string, TryReadField, bool)> Fields => new()
    {
        ("OID", TryReadIdentifierField, true),
        ("NAME", TryReadNameField, false),
        ("DESC", TryReadDescField, false),
        ("OBSOLETE", TryReadObsoleteField, false),
        ("AUX", TryReadAuxField, false),
        ("MUST", TryReadMustField, false),
        ("MAY", TryReadMayField, false),
        ("NOT", TryReadNotField, false),
    };

    public DITContentRuleDescription(string definition) : base(definition) { }

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

        if (Auxiliary.Length > 0)
        {
            string value = AbnfEncoder.EncodeOids(Auxiliary);
            sb.AppendFormat(" AUX {0}", value);
        }

        if (Must.Length > 0)
        {
            string value = AbnfEncoder.EncodeOids(Must);
            sb.AppendFormat(" MUST {0}", value);
        }

        if (May.Length > 0)
        {
            string value = AbnfEncoder.EncodeOids(May);
            sb.AppendFormat(" MAY {0}", value);
        }

        if (Not.Length > 0)
        {
            string value = AbnfEncoder.EncodeOids(Not);
            sb.AppendFormat(" NOT {0}", value);
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

    private bool TryReadMustField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOids(data, out var oids, out charConsumed))
        {
            Must = oids;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadAuxField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOids(data, out var oids, out charConsumed))
        {
            Auxiliary = oids;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadMayField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOids(data, out var oids, out charConsumed))
        {
            May = oids;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadNotField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOids(data, out var oids, out charConsumed))
        {
            Not = oids;
            return true;
        }
        else
        {
            return false;
        }
    }
}
