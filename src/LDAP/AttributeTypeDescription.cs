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
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4512#section-4.1.2">RFC 4512 4.1.2.Attribute Types</see>
public class AttributeTypeDescription
{
    /// <summary>The object identifier assigned to this attribute type.</summary>
    public string OID { get; set; }

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

    /// <summary>Custom extensions of this attribute type.</summary>
    public Dictionary<string, string[]> Extensions { get; set; } = new();

    public AttributeTypeDescription(string definition)
    {
        ReadOnlySpan<char> data = definition.AsSpan();
        if (data.Length < 2 || data[0] != '(')
        {
            throw new FormatException("Invalid AttributeTypeDescription value does not start with '('");
        }
        data = data[1..];

        AbnfDecoder.TryParseWSP(data, out var _, out var read);
        data = data[read..];

        if (!AbnfDecoder.TryParseNumericOid(data, out var numericOid, out read))
        {
            throw new FormatException("Invalid AttributeTypeDescription value has no numericoid value");
        }
        OID = numericOid;
        data = data[read..];

        List<(string, TryReadOptionalField)> fields = new()
        {
            ("NAME", TryReadNameField),
            ("DESC", TryReadDescField),
            ("OBSOLETE", TryReadObsoleteField),
            ("SUP", TryReadSupField),
            ("EQUALITY", TryReadEqualityField),
            ("ORDERING", TryReadOrderingField),
            ("SUBSTR", TryReadSubstrField),
            ("SYNTAX", TryReadSyntaxField),
            ("SINGLE-VALUE", TryReadSingleValueField),
            ("COLLECTIVE", TryReadCollectiveField),
            ("NO-USER-MODIFICATION", TryReadNoUserModificationField),
            ("USAGE", TryReadUsageField),
        };
        foreach ((string field, TryReadOptionalField reader) in fields)
        {
            if (!AbnfDecoder.TryParseSP(data, out var _, out read))
            {
                break;
            }

            if (data[read..].StartsWith(field))
            {
                data = data[read..];

                if (reader(data[field.Length..], out read))
                {
                    data = data[(field.Length + read)..];
                }
                else
                {
                    throw new FormatException($"Invalid AttributeTypeDescription {field} value is invalid");
                }
            }
        }

        AbnfDecoder.TryParseExtensions(data, out var parsedExtensions, out read);
        if (read > 0)
        {
            Extensions = parsedExtensions;
            data = data[read..];
        }

        AbnfDecoder.TryParseWSP(data, out var _, out read);
        data = data[read..];

        if (data.Length != 1 || data[0] != ')')
        {
            throw new FormatException("Invalid AttributeTypeDescription value does not end with ')'");
        }
    }

    public override string ToString()
    {
        StringBuilder sb = new StringBuilder();
        sb.Append($"( {OID}");

        if (Names.Length == 1)
        {
            sb.Append($" NAME '{Names[0]}'");
        }
        else if (Names.Length > 1)
        {
            string names = string.Join("' '", Names);
            sb.Append($" NAME ( '{names}' )");
        }

        if (!string.IsNullOrWhiteSpace(Description))
        {
            string desc = AbnfEncoder.EncodeQDString(Description);
            sb.Append($" DESC {desc}");
        }

        if (Obsolete)
        {
            sb.Append(" OBSOLETE");
        }

        if (!string.IsNullOrWhiteSpace(SuperType))
        {
            sb.Append($" SUP {SuperType}");
        }

        if (!string.IsNullOrWhiteSpace(Equality))
        {
            sb.Append($" EQUALITY {Equality}");
        }

        if (!string.IsNullOrWhiteSpace(Ordering))
        {
            sb.Append($" ORDERING {Ordering}");
        }

        if (!string.IsNullOrWhiteSpace(Substrings))
        {
            sb.Append($" SUBSTR {Substrings}");
        }

        if (!string.IsNullOrWhiteSpace(Syntax))
        {
            sb.Append($" SYNTAX {Syntax}");
            if (SyntaxLength != null)
            {
                sb.Append("{" + SyntaxLength.ToString() + "}");
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
            sb.Append($" {ext.Key} {value}");
        }

        sb.Append(" )");
        return sb.ToString();
    }

    private delegate bool TryReadOptionalField(ReadOnlySpan<char> data, out int charConsumed);

    private bool TryReadNameField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseQDescrs(data, out var names, out read))
        {
            Names = names;
            charConsumed += read;
            return true;
        }
        else
        {
            return false;
        }
    }

    private bool TryReadDescField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseQDString(data, out var desc, out read))
        {
            Description = desc;
            charConsumed += read;
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
        if (TryReadOidField(data, out var oid, out charConsumed))
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
        if (TryReadOidField(data, out var oid, out charConsumed))
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
        if (TryReadOidField(data, out var oid, out charConsumed))
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
        if (TryReadOidField(data, out var oid, out charConsumed))
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

    private bool TryReadOidField(ReadOnlySpan<char> data, out string oid, out int charConsumed)
    {
        oid = "";
        charConsumed = 0;

        if (!AbnfDecoder.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (AbnfDecoder.TryParseOid(data, out oid, out read))
        {
            charConsumed += read;
            return true;
        }
        else
        {
            return false;
        }
    }
}
