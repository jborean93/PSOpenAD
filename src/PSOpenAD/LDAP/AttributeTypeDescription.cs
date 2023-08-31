using System;
using System.Collections.Generic;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>The application of the attribute type.</summary>
public enum AttributeTypeUsage
{
    /// <summary>Attributes of this type represent user information.</summary>
    UserApplications,

    /// <summary>Attributes of this type are directory operational.</summary>
    DirectoryOperation,

    /// <summary>Attributes of this type are DSA-shared usage operational attributes.</summary>
    DistributedOperation,

    /// <summary>Attributes of this type are DSA-specific operational attributes.</summary>
    DsaOperation,
}

/// <summary>Definition of an attribute type.</summary>
/// <remarks>
/// <para>
/// The ABNF notation of an AttributeTypeDescription is:
///     AttributeTypeDescription = LPAREN WSP
///         numericoid                    ; object identifier
///         [ SP "NAME" SP qdescrs ]      ; short names (descriptors)
///         [ SP "DESC" SP qdstring ]     ; description
///         [ SP "OBSOLETE" ]             ; not active
///         [ SP "SUP" SP oid ]           ; supertype
///         [ SP "EQUALITY" SP oid ]      ; equality matching rule
///         [ SP "ORDERING" SP oid ]      ; ordering matching rule
///         [ SP "SUBSTR" SP oid ]        ; substrings matching rule
///         [ SP "SYNTAX" SP noidlen ]    ; value syntax
///         [ SP "SINGLE-VALUE" ]         ; single-value
///         [ SP "COLLECTIVE" ]           ; collective
///         [ SP "NO-USER-MODIFICATION" ] ; not user modifiable
///         [ SP "USAGE" SP usage ]       ; usage
///         extensions WSP RPAREN         ; extensions
///
///     usage = "userApplications"     /  ; user
///             "directoryOperation"   /  ; directory operational
///             "distributedOperation" /  ; DSA-shared operational
///             "dSAOperation"            ; DSA-specific operational
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2">RFC 4512 4.1.2.Attribute Types</see>
public class AttributeTypeDescription : LdapAbnfClass
{
    /// <summary>The object identifier assigned to this attribute type.</summary>
    public string OID { get; set; } = "";

    /// <summary>Short names (descriptors) identifying this attribute type.</summary>
    public string[] Names { get; set; } = Array.Empty<string>();

    /// <summary>The short descriptive string.</summary>
    public string? Description { get; set; }

    /// <summary>Indicates this attribute type is not active.</summary>
    public bool Obsolete { get; set; }

    /// <summary>The OID that specifies the direct supertype of this type.</summary>
    public string? SuperType { get; set; }

    /// <summary>The OID of the equality matching rules.</summary>
    public string? Equality { get; set; }

    /// <summary>The OID of the ordering matching rules.</summary>
    public string? Ordering { get; set; }

    /// <summary>The OID of the substring matching rules.</summary>
    public string? Substrings { get; set; }

    /// <summary>The value syntax object identifier.</summary>
    public string? Syntax { get; set; }

    /// <summary>The minimum upper bound length for this attribute.</summary>
    public int? SyntaxLength { get; set; }

    /// <summary>Indicates attributes of this type are restricted to a single value.</summary>
    public bool SingleValue { get; set; }

    /// <summary>Indicates this attribute type is collective.</summary>
    public bool Collective { get; set; }

    /// <summary>Indicates this attribute type is not user modifiable.</summary>
    public bool NoUserModification { get; set; }

    /// <summary>The application of this attribute type.</summary>
    public AttributeTypeUsage Usage { get; set; } = AttributeTypeUsage.UserApplications;

    internal override List<(string, TryReadField, bool)> Fields => new()
    {
        ("OID", TryReadIdentifierField, true),
        ("NAME", TryReadNameField, false),
        ("DESC", TryReadDescField, false),
        ("OBSOLETE", TryReadObsoleteField, false),
        ("SUP", TryReadSupField, false),
        ("EQUALITY", TryReadEqualityField, false),
        ("ORDERING", TryReadOrderingField, false),
        ("SUBSTR", TryReadSubstrField, false),
        ("SYNTAX", TryReadSyntaxField, false),
        ("SINGLE-VALUE", TryReadSingleValueField, false),
        ("COLLECTIVE", TryReadCollectiveField, false),
        ("NO-USER-MODIFICATION", TryReadNoUserModificationField, false),
        ("USAGE", TryReadUsageField, false),
    };

    public AttributeTypeDescription(string definition) : base(definition) { }

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

        if (!string.IsNullOrWhiteSpace(SuperType))
        {
            sb.AppendFormat(" SUP {0}", SuperType);
        }

        if (!string.IsNullOrWhiteSpace(Equality))
        {
            sb.AppendFormat(" EQUALITY {0}", Equality);
        }

        if (!string.IsNullOrWhiteSpace(Ordering))
        {
            sb.AppendFormat(" ORDERING {0}", Ordering);
        }

        if (!string.IsNullOrWhiteSpace(Substrings))
        {
            sb.AppendFormat(" SUBSTR {0}", Substrings);
        }

        if (!string.IsNullOrWhiteSpace(Syntax))
        {
            sb.AppendFormat(" SYNTAX {0}", Syntax);
            if (SyntaxLength != null)
            {
                sb.Append("{").Append(SyntaxLength.ToString()).Append("}");
            }
        }

        if (SingleValue)
        {
            sb.Append(" SINGLE-VALUE");
        }

        if (Collective)
        {
            sb.Append(" COLLECTIVE");
        }

        if (NoUserModification)
        {
            sb.Append(" NO-USER-MODIFICATION");
        }

        switch (Usage)
        {
            case AttributeTypeUsage.DirectoryOperation:
                sb.Append(" USAGE directoryOperation");
                break;

            case AttributeTypeUsage.DistributedOperation:
                sb.Append(" USAGE distributedOperation");
                break;

            case AttributeTypeUsage.DsaOperation:
                sb.Append(" USAGE dSAOperation");
                break;
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

    private bool TryReadSupField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOid(data, out var oid, out charConsumed))
        {
            SuperType = oid;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadEqualityField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOid(data, out var oid, out charConsumed))
        {
            Equality = oid;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadOrderingField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOid(data, out var oid, out charConsumed))
        {
            Ordering = oid;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadSubstrField(ReadOnlySpan<char> data, out int charConsumed)
    {
        if (TryReadOid(data, out var oid, out charConsumed))
        {
            Substrings = oid;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadSyntaxField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseNOidLen(data, out var oid, out var oidLen, out read))
        {
            Syntax = oid;
            if (oidLen != null)
            {
                SyntaxLength = int.Parse(oidLen);
            }
            charConsumed += read;
            return true;
        }
        else if (AbnfDecoder.TryParseQDString(data, out oid, out read))
        {
            // While not parse of the spec for this field ActiveDirectory effectively returns a qdstring value here
            // instead of an oid. This handles that scenario while trying the actual spec definition first.
            Syntax = oid;
            charConsumed += read;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadSingleValueField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        SingleValue = true;
        return true;
    }

    private bool TryReadCollectiveField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        Collective = true;
        return true;
    }

    private bool TryReadNoUserModificationField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;
        NoUserModification = true;
        return true;
    }

    private bool TryReadUsageField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseKeyString(data, out var usage, out read))
        {
            switch (usage)
            {
                case "userApplications":
                    Usage = AttributeTypeUsage.UserApplications;
                    break;
                case "directoryOperation":
                    Usage = AttributeTypeUsage.DirectoryOperation;
                    break;
                case "distributedOperation":
                    Usage = AttributeTypeUsage.DistributedOperation;
                    break;
                case "dSAOperation":
                    Usage = AttributeTypeUsage.DsaOperation;
                    break;
                default:
                    return false;
            }

            charConsumed += read;
            return true;
        }
        else
        {
            return false;
        }
    }
}
