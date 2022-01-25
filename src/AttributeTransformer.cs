using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

[assembly: InternalsVisibleTo("PSOpenADTests")]
namespace PSOpenAD;

internal static class DefaultOverrider
{
    public delegate object CustomTransform(string attribute, ReadOnlySpan<byte> value);

    internal static Dictionary<string, CustomTransform> Overrides { get; } = DefaultOverrides();

    private static Dictionary<string, CustomTransform> DefaultOverrides()
    {
        // These are known attributes that can map to a more user friendly value. Unfortunately these details
        // aren't stored in the schema so they need to be manually mapped.
        return new Dictionary<string, CustomTransform>()
        {
            { "accountExpires", (_, v) => ParseFileTimeValue(v) },
            { "badPasswordTime", (_, v) => ParseFileTimeValue(v) },
            { "creationTime", (_, v) => ParseFileTimeValue(v) },
            { "forceLogoff", (_, v) => ParseTimeSpanValue(v) },
            { "groupType", (_, v) => (GroupType)(int)SyntaxDefinition.ReadInteger(v) },
            { "instanceType", (_, v) => (InstanceType)(int)SyntaxDefinition.ReadInteger(v) },
            { "lastLogoff", (_, v) => ParseFileTimeValue(v) },
            { "lastLogon", (_, v) => ParseFileTimeValue(v) },
            { "lastLogonTimestamp", (_, v) => ParseFileTimeValue(v) },
            { "lockoutDuration", (_, v) => ParseTimeSpanValue(v) },
            { "lockOutObservationWindow", (_, v) => ParseTimeSpanValue(v) },
            { "maxPwdAge", (_, v) => ParseTimeSpanValue(v) },
            { "minPwdAge", (_, v) => ParseTimeSpanValue(v) },
            { "msDFS-GenerationGUIDv2", (_, v) => new Guid(v) },
            { "msDFS-LinkIdentityGUIDv2", (_, v) => new Guid(v) },
            { "msDFS-NamespaceIdentityGUIDv2", (_, v) => new Guid(v) },
            { "msDFS-TargetListv2", (_, v) => Encoding.Unicode.GetString(v ) },
            { "msDFSR-ContentSetGuid", (_, v) => new Guid(v) },
            { "msDFSR-ReplicationGroupGuid", (_, v) => new Guid(v) },
            { "msDS-SupportedEncryptionTypes", (
                (_, v) => (SupportedEncryptionTypes)(int)SyntaxDefinition.ReadInteger(v)
            ) },
            { "objectGUID", (_, v) => new Guid(v) },
            { "objectSid", (_, v) => new SecurityIdentifier(v.ToArray(), 0) },
            { "priorSetTime", (_, v) => ParseFileTimeValue(v) },
            { "pwdLastSet", (_, v) => ParseFileTimeValue(v) },
            { "pwdProperties", (_, v) => (PasswordProperties)(int)SyntaxDefinition.ReadInteger(v) },
            { "sAMAccountType", (_, v) => (SAMAccountType)(int)SyntaxDefinition.ReadInteger(v) },
            { "systemFlags", (_, v) => (SystemFlags)(int)SyntaxDefinition.ReadInteger(v) },
            { "userAccountControl", (_, v) => (UserAccountControl)(int)SyntaxDefinition.ReadInteger(v) },
            { "userCertificate", (_, v) => new X509Certificate2(v.ToArray() ) },
        };
    }

    internal static TimeSpan ParseTimeSpanValue(ReadOnlySpan<byte> value)
    {
        Int64 raw = (Int64)SyntaxDefinition.ReadInteger(value);
        if (raw == Int64.MaxValue)
            return new TimeSpan(0);
        else
            return new TimeSpan(raw);
    }

    internal static DateTimeOffset ParseFileTimeValue(ReadOnlySpan<byte> value)
    {
        Int64 raw = (Int64)SyntaxDefinition.ReadInteger(value);
        if (raw == Int64.MaxValue)
            return new DateTimeOffset(DateTime.FromFileTimeUtc(0));
        else
            return new DateTimeOffset(DateTime.FromFileTimeUtc(raw));
    }
}

internal sealed class AttributeTransformer
{
    private readonly Dictionary<string, AttributeTypeDescription> _typeInformation;

    public AttributeTransformer(Dictionary<string, AttributeTypeDescription> typeInformation)
    {
        _typeInformation = typeInformation;
    }

    public void RegisterTransformer(string attribute, DefaultOverrider.CustomTransform transformer)
        => DefaultOverrider.Overrides[attribute] = transformer;

    public (PSObject[], bool) Transform(string attribute, IList<byte[]> value, PSCmdlet? cmdlet)
    {
        AttributeTypeDescription? attrInfo = null;
        if (_typeInformation.ContainsKey(attribute))
            attrInfo = _typeInformation[attribute];

        string oidSyntax = attrInfo?.Syntax ?? "Unknown";

        DefaultOverrider.CustomTransform? customTransform = null;
        if (DefaultOverrider.Overrides.ContainsKey(attribute))
            customTransform = DefaultOverrider.Overrides[attribute];

        List<PSObject> processed = new();
        foreach (byte[] val in value)
        {
            PSObject parsed;
            try
            {
                object raw;
                if (customTransform != null)
                {
                    raw = customTransform(attribute, val);
                }
                else
                {
                    raw = ProcessAttributeValue(oidSyntax, val);
                }

                parsed = PSObject.AsPSObject(raw);
                parsed.Properties.Add(new PSNoteProperty("RawValue", val));
            }
            catch (Exception e)
            {
                ErrorRecord rec = new(e, "AttributeParserError", ErrorCategory.ParserError, val);
                rec.ErrorDetails = new($"Failed to parse {attribute} (OID '{oidSyntax}') - {e.Message}");
                cmdlet?.WriteError(rec);

                parsed = PSObject.AsPSObject(val);
            }

            processed.Add(parsed);
        }

        return (processed.ToArray(), attrInfo?.SingleValue ?? false);
    }

    private static object ProcessAttributeValue(string oid, ReadOnlySpan<byte> value) => oid switch
    {
        // RFC 4517 defined OIDs - Also in RFC 2252
        // https://datatracker.ietf.org/doc/html/rfc4517#section-3.3
        // "1.3.6.1.4.1.1466.115.121.1.1" => ACI Item - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.2" => Access Point - RFC 4517 Appx B. 21 - No longer defined.
        "1.3.6.1.4.1.1466.115.121.1.3" => SyntaxDefinition.ReadAttributeTypeDescription(value),
        // "1.3.6.1.4.1.1466.115.121.1.4" => Audio - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.5" => Binary - RFC 4517 Appx B. 12 - Removed.
        "1.3.6.1.4.1.1466.115.121.1.6" => SyntaxDefinition.ReadBitString(value),
        "1.3.6.1.4.1.1466.115.121.1.7" => SyntaxDefinition.ReadBoolean(value),
        // "1.3.6.1.4.1.1466.115.121.1.8" => Certificate - RFC 4517 Appx B. 17 - While defined in RFC 4523 AD doesn't use it.
        // "1.3.6.1.4.1.1466.115.121.1.9" => Certificate List - RFC 4517 Appx B. 17 - While defined in RFC 4523 AD doesn't use it.
        // "1.3.6.1.4.1.1466.115.121.1.10" => Certificate Pair - RFC 4517 Appx B. 17 - While defined in RFC 4523 AD doesn't use it.
        "1.3.6.1.4.1.1466.115.121.1.11" => SyntaxDefinition.ReadCountryString(value),
        "1.3.6.1.4.1.1466.115.121.1.12" => SyntaxDefinition.ReadDN(value),
        // "1.3.6.1.4.1.1466.115.121.1.13" => Data Quality Syntax - RFC 4517 Appx B. 21 - No longer defined.
        "1.3.6.1.4.1.1466.115.121.1.14" => SyntaxDefinition.ReadDeliveryMethod(value),
        "1.3.6.1.4.1.1466.115.121.1.15" => SyntaxDefinition.ReadDirectoryString(value),
        "1.3.6.1.4.1.1466.115.121.1.16" => SyntaxDefinition.ReadDITContentRuleDescription(value),
        "1.3.6.1.4.1.1466.115.121.1.17" => SyntaxDefinition.ReadDITStructureRuleDescription(value),
        // "1.3.6.1.4.1.1466.115.121.1.18" => DL Submit Permission - RFC 4517 Appx B. 19 - Removed.
        // "1.3.6.1.4.1.1466.115.121.1.19" => DSA Quality Syntax - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.20" => DSE Type - RFC 4517 Appx B. 21 - No longer defined.
        "1.3.6.1.4.1.1466.115.121.1.21" => SyntaxDefinition.ReadEnhancedGuide(value),
        "1.3.6.1.4.1.1466.115.121.1.22" => SyntaxDefinition.ReadFacsimileTelephoneNumber(value),
        "1.3.6.1.4.1.1466.115.121.1.23" => SyntaxDefinition.ReadFax(value),
        "1.3.6.1.4.1.1466.115.121.1.24" => SyntaxDefinition.ReadGeneralizedTime(value),
        "1.3.6.1.4.1.1466.115.121.1.25" => SyntaxDefinition.ReadGuide(value),
        "1.3.6.1.4.1.1466.115.121.1.26" => SyntaxDefinition.ReadIA5String(value),
        "1.3.6.1.4.1.1466.115.121.1.27" => SyntaxDefinition.ReadInteger(value),
        "1.3.6.1.4.1.1466.115.121.1.28" => SyntaxDefinition.ReadJPEG(value),
        // "1.3.6.1.4.1.1466.115.121.1.29" => Master and Shadow Access Points - RFC 4517 Appx B. 21 - No longer defined.
        "1.3.6.1.4.1.1466.115.121.1.30" => SyntaxDefinition.ReadMatchingRuleDescription(value),
        "1.3.6.1.4.1.1466.115.121.1.31" => SyntaxDefinition.ReadMatchingRuleUseDescription(value),
        // "1.3.6.1.4.1.1466.115.121.1.32" => Mail Preference - RFC 4517 Appx B. 22 - Removed.
        // "1.3.6.1.4.1.1466.115.121.1.33" => MHS OR Address- RFC 4517 Appx B. 18 - Removed.
        "1.3.6.1.4.1.1466.115.121.1.34" => SyntaxDefinition.ReadNameAndOptionalUID(value),
        "1.3.6.1.4.1.1466.115.121.1.35" => SyntaxDefinition.ReadNameFormDescription(value),
        "1.3.6.1.4.1.1466.115.121.1.36" => SyntaxDefinition.ReadNumericString(value),
        "1.3.6.1.4.1.1466.115.121.1.37" => SyntaxDefinition.ReadObjectClassDescription(value),
        "1.3.6.1.4.1.1466.115.121.1.38" => SyntaxDefinition.ReadOID(value),
        "1.3.6.1.4.1.1466.115.121.1.39" => SyntaxDefinition.ReadOtherMailbox(value),
        "1.3.6.1.4.1.1466.115.121.1.40" => SyntaxDefinition.ReadOctetString(value),
        "1.3.6.1.4.1.1466.115.121.1.41" => SyntaxDefinition.ReadPostalAddress(value),
        // "1.3.6.1.4.1.1466.115.121.1.42" => Protocol Information - RFC 4517 Appx B. 21 - No longer defined.
        "1.3.6.1.4.1.1466.115.121.1.43" => SyntaxDefinition.ReadPresentationAddress(value), // Technically removed but AD still uses it.
        "1.3.6.1.4.1.1466.115.121.1.44" => SyntaxDefinition.ReadPrintableString(value),
        // "1.3.6.1.4.1.1466.115.121.1.45" => Subtree Specification - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.46" => Supplier Information - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.47" => Supplier Or Consumer - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.48" => Supplier And Consumer - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.49" => Supported Algorithm - RFC 4517 Appx B. 17 - While defined in RFC 4523 AD doesn't use it.
        "1.3.6.1.4.1.1466.115.121.1.50" => SyntaxDefinition.ReadTelephoneNumber(value),
        "1.3.6.1.4.1.1466.115.121.1.51" => SyntaxDefinition.ReadTeletexTerminalIdentifier(value),
        "1.3.6.1.4.1.1466.115.121.1.52" => SyntaxDefinition.ReadTelexNumber(value),
        "1.3.6.1.4.1.1466.115.121.1.53" => SyntaxDefinition.ReadUTCTime(value),
        "1.3.6.1.4.1.1466.115.121.1.54" => SyntaxDefinition.ReadLDAPSyntaxDescription(value),
        // "1.3.6.1.4.1.1466.115.121.1.55" => Modify Rights - RFC 4517 Appx B. 21 - No longer defined.
        // "1.3.6.1.4.1.1466.115.121.1.56" => LDAP Schema Definition - RFC 4517 Appx B. 22 - Removed.
        // "1.3.6.1.4.1.1466.115.121.1.57" => LDAP Schema Description - RFC 4517 Appx B. 21 - No longer defined.
        "1.3.6.1.4.1.1466.115.121.1.58" => SyntaxDefinition.ReadSubstringAssertion(value),

        // Microsoft defined OIDs
        // These aren't defined in the LDAP spec so the conversion is done here.
        // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/68d2bb5e-764a-48ec-9841-a5fa429c4556
        "1.2.840.113556.1.4.903" => SyntaxDefinition.ReadDirectoryString(value), // DNWithOctetString
        "1.2.840.113556.1.4.904" => SyntaxDefinition.ReadDirectoryString(value), // DNWithString
        "1.2.840.113556.1.4.905" => SyntaxDefinition.ReadDirectoryString(value), // OR-Name
        "1.2.840.113556.1.4.906" => (Int64)SyntaxDefinition.ReadInteger(value), // Large-Integer
        "1.2.840.113556.1.4.907" => SyntaxDefinition.ReadOctetString(value), // Object-Security-Descriptor
        "1.2.840.113556.1.4.1221" => SyntaxDefinition.ReadDirectoryString(value), // CaseIgnoreString
        "1.2.840.113556.1.4.1362" => SyntaxDefinition.ReadDirectoryString(value), // CaseExactString
        "OctetString" => SyntaxDefinition.ReadOctetString(value), // Weird syntax but AD does send this

        _ => throw new NotImplementedException($"OID '{oid}' not recognised"),
    };
}
