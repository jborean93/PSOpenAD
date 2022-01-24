using System;
using System.Collections.Generic;

namespace PSOpenAD.LDAP;

public enum AttributeTypeUsage
{
    NotSpecified,
    UserApplications,
    DirectoryOperation,
    DistributedOperation,
    DsaOperation,
}

public class AttributeTypeDescription
{
    public string OID { get; set; }
    public string[] Names { get; set; } = Array.Empty<string>();
    public string? Description { get; set; }
    public bool Obsolete { get; set; }
    public string? SuperType { get; set; }
    public string? Equality { get; set; }
    public string? Ordering { get; set; }
    public string? Substrings { get; set; }
    public string? Syntax { get; set; }
    public int? SyntaxLength { get; set; }
    public bool SingleValue { get; set; }
    public bool Collective { get; set; }
    public bool NoUserModification { get; set; }
    public AttributeTypeUsage Usage { get; set; } = AttributeTypeUsage.NotSpecified;

    public Dictionary<string, string[]> Extensions { get; set; } = new();

    public AttributeTypeDescription(string definition)
    {
        ReadOnlySpan<char> data = definition.AsSpan();
        if (data.Length < 2 || data[0] != '(')
        {
            throw new FormatException("Invalid AttributeTypeDescription value does not start with '('");
        }
        data = data[1..];

        LdapAbnfDefinitions.TryParseWSP(data, out var _, out var read);
        data = data[read..];

        if (!LdapAbnfDefinitions.TryParseNumericOid(data, out var numericOid, out read))
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
            if (!LdapAbnfDefinitions.TryParseSP(data, out var _, out read))
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

        LdapAbnfDefinitions.TryParseExtensions(data, out var parsedExtensions, out read);
        if (read > 0)
        {
            Extensions = parsedExtensions;
            data = data[read..];
        }

        LdapAbnfDefinitions.TryParseWSP(data, out var _, out read);
        data = data[read..];

        if (data.Length != 1 || data[0] != ')')
        {
            throw new FormatException("Invalid AttributeTypeDescription value does not end with ')'");
        }
    }

    private delegate bool TryReadOptionalField(ReadOnlySpan<char> data, out int charConsumed);

    private bool TryReadNameField(ReadOnlySpan<char> data, out int charConsumed)
    {
        charConsumed = 0;

        if (!LdapAbnfDefinitions.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (LdapAbnfDefinitions.TryParseQDescrs(data, out var names, out read))
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

        if (!LdapAbnfDefinitions.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (LdapAbnfDefinitions.TryParseQDString(data, out var desc, out read))
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

        if (!LdapAbnfDefinitions.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (LdapAbnfDefinitions.TryParseNOidLen(data, out var oid, out var oidLen, out read))
        {
            Syntax = oid;
            if (oidLen != null)
            {
                SyntaxLength = int.Parse(oidLen);
            }
            charConsumed += read;
            return true;
        }
        else if (LdapAbnfDefinitions.TryParseQDString(data, out oid, out read))
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

        if (!LdapAbnfDefinitions.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (LdapAbnfDefinitions.TryParseKeyString(data, out var usage, out read))
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

        if (!LdapAbnfDefinitions.TryParseSP(data, out var _, out var read))
        {
            return false;
        }
        data = data[read..];
        charConsumed += read;

        if (LdapAbnfDefinitions.TryParseOid(data, out oid, out read))
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
