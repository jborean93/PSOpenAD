using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>Definition of a DIT structure rule.</summary>
/// <remarks>
/// <para>
/// The ABNF notation of an DITStructureRuleDescription is:
///     DITStructureRuleDescription = LPAREN WSP
///         ruleid                     ; rule identifier
///         [ SP "NAME" SP qdescrs ]   ; short names (descriptors)
///         [ SP "DESC" SP qdstring ]  ; description
///         [ SP "OBSOLETE" ]          ; not active
///         SP "FORM" SP oid           ; NameForm
///         [ SP "SUP" ruleids ]       ; superior rules
///         extensions WSP RPAREN      ; extensions
///
///     ruleids = ruleid / ( LPAREN WSP ruleidlist WSP RPAREN )
///     ruleidlist = ruleid *( SP ruleid )
///     ruleid = number
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.7.1">RFC 4512 4.1.7.1. DIT Structure Rules</see>
public class DITStructureRuleDescription : LdapAbnfClass
{
    /// <summary>The DIT content rule identifier.</summary>
    public string Id { get; set; } = "";

    /// <summary>Short names (descriptors) identifying this DIT structure rule.</summary>
    public string[] Names { get; set; } = Array.Empty<string>();

    /// <summary>The short descriptive string.</summary>
    public string? Description { get; set; }

    /// <summary>Indicates this DIT structure rule is not active.</summary>
    public bool Obsolete { get; set; }

    /// <summary>The name form associated with this DIT structure rule.</summary>
    public string Form { get; set; } = "";

    /// <summary>Identifies superior rules (by rule id).</summary>
    public string[] SuperRules { get; set; } = Array.Empty<string>();

    internal override List<(string, TryReadField, bool)> Fields => new()
    {
        ("ID", TryReadIdentifierField, true),
        ("NAME", TryReadNameField, false),
        ("DESC", TryReadDescField, false),
        ("OBSOLETE", TryReadObsoleteField, false),
        ("FORM", TryReadFormField, true),
        ("SUP", TryReadSupField, false),
    };

    public DITStructureRuleDescription(string definition) : base(definition) { }

    public override string ToString()
    {
        StringBuilder sb = new();
        sb.AppendFormat("( {0}", Id);

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

        sb.AppendFormat(" FORM {0}", Form);

        if (SuperRules.Length > 0)
        {
            sb.Append(" SUP ");

            if (SuperRules.Length == 1)
            {
                sb.Append(SuperRules[0]);
            }
            else
            {
                sb.Append("( ");
                sb.AppendJoin(" ", SuperRules);
                sb.Append(" )");
            }
        }

        foreach (KeyValuePair<string, string[]> ext in Extensions)
        {
            string value = AbnfEncoder.EncodeQDStrings(ext.Value);
            sb.AppendFormat(" {0} {1}", ext.Key, value);
        }

        sb.Append(" )");
        return sb.ToString();
    }

    private bool TryReadIdentifierField(ReadOnlySpan<char> data, out int charsConsumed)
    {
        if (AbnfDecoder.TryParseNumber(data, out var number, out charsConsumed))
        {
            Id = number;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadNameField(ReadOnlySpan<char> data, out int charsConsumed)
    {
        if (TryReadQDescrs(data, out var value, out charsConsumed))
        {
            Names = value;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadDescField(ReadOnlySpan<char> data, out int charsConsumed)
    {
        if (TryReadQDString(data, out var value, out charsConsumed))
        {
            Description = value;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadObsoleteField(ReadOnlySpan<char> data, out int charsConsumed)
    {
        charsConsumed = 0;
        Obsolete = true;
        return true;
    }

    private bool TryReadFormField(ReadOnlySpan<char> data, out int charsConsumed)
    {
        if (TryReadOid(data, out var oid, out charsConsumed))
        {
            Form = oid;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadSupField(ReadOnlySpan<char> data, out int charsConsumed)
    {
        charsConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charsConsumed += read;

        if (AbnfDecoder.TryParseValueList(data, out var values, out read, AbnfDecoder.TryParseNumber))
        {
            SuperRules = values;
            charsConsumed += read;
            return true;
        }
        else
        {
            charsConsumed = 0;
            return false;
        }
    }
}
