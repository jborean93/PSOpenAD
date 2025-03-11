using PSOpenAD.LDAP;
using PSOpenAD.Security;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSOpenAD;

internal static class DefaultOverrider
{
    public delegate (object, bool?) CustomTransform(string attribute, ReadOnlySpan<byte> value);

    internal static Dictionary<string, CustomTransform> Overrides { get; } = DefaultOverrides();

    private static PSCodeMethod OidToStringMethod = new(
        "ToString",
        typeof(DefaultOverrider).GetMethod(nameof(OidToString), BindingFlags.Public | BindingFlags.Static)!);

    private static Dictionary<string, CustomTransform> DefaultOverrides()
    {

        return new Dictionary<string, CustomTransform>()
        {
            // These are known attributes that can map to a more user friendly value. Unfortunately these details
            // aren't stored in the schema so they need to be manually mapped.
            { "accountExpires", (_, v) => ParseFileTimeValue(v) },
            { "badPasswordTime", (_, v) => ParseFileTimeValue(v) },
            { "creationTime", (_, v) => ParseFileTimeValue(v) },
            { "forceLogoff", (_, v) => ParseTimeSpanValue(v) },
            { "groupType", (_, v) => ParseEnumValue<GroupType>(v) },
            { "instanceType", (_, v) => ParseEnumValue<InstanceType>(v) },
            { "lastLogoff", (_, v) => ParseFileTimeValue(v) },
            { "lastLogon", (_, v) => ParseFileTimeValue(v) },
            { "lastLogonTimestamp", (_, v) => ParseFileTimeValue(v) },
            { "lockoutDuration", (_, v) => ParseTimeSpanValue(v) },
            { "lockOutObservationWindow", (_, v) => ParseTimeSpanValue(v) },
            { "maxPwdAge", (_, v) => ParseTimeSpanValue(v) },
            { "minPwdAge", (_, v) => ParseTimeSpanValue(v) },
            { "msDFS-GenerationGUIDv2", (_, v) => (new Guid(v), null) },
            { "msDFS-LinkIdentityGUIDv2", (_, v) => (new Guid(v), null) },
            { "msDFS-NamespaceIdentityGUIDv2", (_, v) => (new Guid(v), null) },
            { "msDFS-TargetListv2", (_, v) => (Encoding.Unicode.GetString(v), null) },
            { "msDFSR-ContentSetGuid", (_, v) => (new Guid(v), null) },
            { "msDFSR-ReplicationGroupGuid", (_, v) => (new Guid(v), null) },
            { "msDS-SupportedEncryptionTypes", (_, v) => ParseEnumValue<SupportedEncryptionTypes>(v) },
            { "objectGUID", (_, v) => (new Guid(v), null) },
            { "objectSid", (_, v) => (new SecurityIdentifier(v), null) },
            { "priorSetTime", (_, v) => ParseFileTimeValue(v) },
            { "pwdLastSet", (_, v) => ParseFileTimeValue(v) },
            { "pwdProperties", (_, v) => ParseEnumValue<PasswordProperties>(v) },
            { "sAMAccountType", (_, v) => ParseEnumValue<SAMAccountType>(v) },
            { "systemFlags", (_, v) => ParseEnumValue<SystemFlags>(v) },
            { "userAccountControl", (_, v) => ParseEnumValue<UserAccountControl>(v) },
            { "userCertificate", (_, v) => (new X509Certificate2(v.ToArray()), null ) },

            // These are the RootDSE attributes that aren't present in the schema so manually define them.
            // Non-operational (default)
            { "configurationNamingContext", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "currentTime", (_, v) => (SyntaxDefinition.ReadUTCTime(v), true) },
            { "defaultNamingContext", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "dnsHostName", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "domainControllerFunctionality", (_, v) => ParseEnumValue<ADDomainControllerMode>(v, isSingleValue: true) },
            { "domainFunctionality", (_, v) => ParseEnumValue<ADDomainMode>(v, isSingleValue: true) },
            { "dsServiceName", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "forestFunctionality", (_, v) => ParseEnumValue<ADForestMode>(v, isSingleValue: true) },
            { "highestCommittedUSN", (_, v) => ((long)SyntaxDefinition.ReadInteger(v), true) },
            { "isGlobalCatalogReady", (_, v) => (SyntaxDefinition.ReadDirectoryString(v) == "TRUE", true) },
            { "isSynchronized", (_, v) => (SyntaxDefinition.ReadDirectoryString(v) == "TRUE", true) },
            { "ldapServiceName", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "rootDomainNamingContext", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "schemaNamingContext", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "serverName", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "subschemaSubentry", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "supportedCapabilities", (_, v) => ParseOidValue(v) },
            { "supportedControl", (_, v) => ParseOidValue(v) },
            { "supportedLDAPVersion", (_, v) => ((long)SyntaxDefinition.ReadInteger(v), false) },

            // Operational (explicitly requested)
            { "dsSchemaAttrCount", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
            { "dsSchemaClassCount", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
            { "dsSchemaPrefixCount", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
            { "supportedExtension", (_, v) => ParseOidValue(v) },
            { "dsaVersionString", (_, v) => (SyntaxDefinition.ReadDirectoryString(v), true) },
            { "msDS-PortLDAP", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
            { "msDS-PortSSL", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
            { "spnRegistrationResult", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
            { "tokenGroups", (_, v) => (new SecurityIdentifier(v), false) },
            { "usnAtRifm", (_, v) => ((long)SyntaxDefinition.ReadInteger(v), true) },
            { "approximateHighestInternalObjectID", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
            { "databaseGuid", (_, v) => (new Guid(SyntaxDefinition.ReadDirectoryString(v)), true) },
            { "schemaIndexUpdateState", (_, v) => ((int)SyntaxDefinition.ReadInteger(v), true) },
        };
    }

    internal static (TimeSpan, bool?) ParseTimeSpanValue(ReadOnlySpan<byte> value)
    {
        Int64 raw = (Int64)SyntaxDefinition.ReadInteger(value);
        if (raw == Int64.MaxValue)
            return (new TimeSpan(0), null);
        else
            return (new TimeSpan(raw), null);
    }

    internal static (DateTimeOffset, bool?) ParseFileTimeValue(ReadOnlySpan<byte> value)
    {
        Int64 raw = (Int64)SyntaxDefinition.ReadInteger(value);
        if (raw == Int64.MaxValue)
            return (new DateTimeOffset(DateTime.FromFileTimeUtc(0)), null);
        else
            return (new DateTimeOffset(DateTime.FromFileTimeUtc(raw)), null);
    }

    internal static (T, bool?) ParseEnumValue<T>(ReadOnlySpan<byte> value, bool? isSingleValue = null)
    {
        int raw = (int)SyntaxDefinition.ReadInteger(value);
        return ((T)Enum.ToObject(typeof(T), raw), isSingleValue);
    }

    internal static (Oid, bool?) ParseOidValue(ReadOnlySpan<byte> value)
    {
        Dictionary<string, string> oidLookup = new()
        {
            // Known extended controls
            { PagedResultControl.LDAP_PAGED_RESULT_OID_STRING, nameof(PagedResultControl.LDAP_PAGED_RESULT_OID_STRING) },
            { ShowDeleted.LDAP_SERVER_SHOW_DELETED_OID, nameof(ShowDeleted.LDAP_SERVER_SHOW_DELETED_OID) },
            { "1.2.840.113556.1.4.473", "LDAP_SERVER_SORT_OID" },
            { "1.2.840.113556.1.4.474", "LDAP_SERVER_RESP_SORT_OID" },
            { "1.2.840.113556.1.4.521", "LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID" },
            { "1.2.840.113556.1.4.528", "LDAP_SERVER_NOTIFICATION_OID" },
            { "1.2.840.113556.1.4.529", "LDAP_SERVER_EXTENDED_DN_OID" },
            { "1.2.840.113556.1.4.619", "LDAP_SERVER_LAZY_COMMIT_OID" },
            { "1.2.840.113556.1.4.801", "LDAP_SERVER_SD_FLAGS_OID" },
            { "1.2.840.113556.1.4.802", "LDAP_SERVER_RANGE_OPTION_OID" },
            { "1.2.840.113556.1.4.805", "LDAP_SERVER_TREE_DELETE_OID" },
            { "1.2.840.113556.1.4.841", "LDAP_SERVER_DIRSYNC_OID" },
            { "1.2.840.113556.1.4.970", "LDAP_SERVER_GET_STATS_OID" },
            { "1.2.840.113556.1.4.1338", "LDAP_SERVER_VERIFY_NAME_OID" },
            { "1.2.840.113556.1.4.1339", "LDAP_SERVER_DOMAIN_SCOPE_OID" },
            { "1.2.840.113556.1.4.1340", "LDAP_SERVER_SEARCH_OPTIONS_OID" },
            { "1.2.840.113556.1.4.1341", "LDAP_SERVER_RODC_DCPROMO_OID" },
            { "1.2.840.113556.1.4.1413", "LDAP_SERVER_PERMISSIVE_MODIFY_OID" },
            { "1.2.840.113556.1.4.1504", "LDAP_SERVER_ASQ_OID" },
            { "1.2.840.113556.1.4.1852", "LDAP_SERVER_QUOTA_CONTROL_OID" },
            { "1.2.840.113556.1.4.1907", "LDAP_SERVER_SHUTDOWN_NOTIFY_OID" },
            { "1.2.840.113556.1.4.1948", "LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID" },
            { "1.2.840.113556.1.4.1974", "LDAP_SERVER_FORCE_UPDATE_OID" },
            { "1.2.840.113556.1.4.2026", "LDAP_SERVER_DN_INPUT_OID" },
            { "1.2.840.113556.1.4.2064", "LDAP_SERVER_SHOW_RECYCLED_OID" },
            { ShowDeactivatedLink.LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID, nameof(ShowDeactivatedLink.LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID) },
            { "1.2.840.113556.1.4.2066", "LDAP_SERVER_POLICY_HINTS_DEPRECATED_OID" },
            { "1.2.840.113556.1.4.2090", "LDAP_SERVER_DIRSYNC_EX_OID" },
            { "1.2.840.113556.1.4.2204", "LDAP_SERVER_TREE_DELETE_EX_OID" },
            { "1.2.840.113556.1.4.2205", "LDAP_SERVER_UPDATE_STATS_OID" },
            { "1.2.840.113556.1.4.2206", "LDAP_SERVER_SEARCH_HINTS_OID" },
            { "1.2.840.113556.1.4.2211", "LDAP_SERVER_EXPECTED_ENTRY_COUNT_OID" },
            { "1.2.840.113556.1.4.2239", "LDAP_SERVER_POLICY_HINTS_OID" },
            { "1.2.840.113556.1.4.2255", "LDAP_SERVER_SET_OWNER_OID" },
            { "1.2.840.113556.1.4.2256", "LDAP_SERVER_BYPASS_QUOTA_OID" },
            { "1.2.840.113556.1.4.2309", "LDAP_SERVER_LINK_TTL_OID" },
            { "1.2.840.113556.1.4.2330", "LDAP_SERVER_SET_CORRELATION_ID_OID" },
            { "1.2.840.113556.1.4.2354", "LDAP_SERVER_THREAD_TRACE_OVERRIDE_OID" },
            { "2.16.840.1.113730.3.4.9", "LDAP_CONTROL_VLVREQUEST" },
            { "2.16.840.1.113730.3.4.10", "LDAP_CONTROL_VLVRESPONSE" },

            // Known extended capabilities
            { "1.2.840.113556.1.4.800", "LDAP_CAP_ACTIVE_DIRECTORY_OID" },
            { "1.2.840.113556.1.4.1670", "LDAP_CAP_ACTIVE_DIRECTORY_V51_OID" },
            { "1.2.840.113556.1.4.1791", "LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID" },
            { "1.2.840.113556.1.4.1851", "LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID" },
            { "1.2.840.113556.1.4.1880", "LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST_OID" },
            { "1.2.840.113556.1.4.1920", "LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID" },
            { "1.2.840.113556.1.4.1935", "LDAP_CAP_ACTIVE_DIRECTORY_V61_OID" },
            { "1.2.840.113556.1.4.2080", "LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID" },
            { "1.2.840.113556.1.4.2237", "LDAP_CAP_ACTIVE_DIRECTORY_W8_OID" },

            // Known extended operations
            { ExtendedOperations.LDAP_SERVER_FAST_BIND_OID, nameof(ExtendedOperations.LDAP_SERVER_FAST_BIND_OID) },
            { ExtendedOperations.LDAP_SERVER_BATCH_REQUEST_OID, nameof(ExtendedOperations.LDAP_SERVER_BATCH_REQUEST_OID) },
            { ExtendedOperations.LDAP_TTL_REFRESH_OID, nameof(ExtendedOperations.LDAP_TTL_REFRESH_OID) },
            { ExtendedOperations.LDAP_SERVER_START_TLS_OID, nameof(ExtendedOperations.LDAP_SERVER_START_TLS_OID) },
            { ExtendedOperations.LDAP_SERVER_WHO_AM_I_OID, nameof(ExtendedOperations.LDAP_SERVER_WHO_AM_I_OID) },
        };
        string raw = SyntaxDefinition.ReadDirectoryString(value);

        Oid oid;
        if (oidLookup.ContainsKey(raw))
        {
            oid = new(raw, oidLookup[raw]);
        }
        else
        {
            oid = new(raw);
        }
        PSObject.AsPSObject(oid).Members.Add(OidToStringMethod);

        return (oid, null);
    }

    public static string OidToString(PSObject value)
    {
        Oid oid = (Oid)value.BaseObject;
        return string.IsNullOrWhiteSpace(oid.FriendlyName) ? oid.Value! : $"{oid.Value} ({oid.FriendlyName})";
    }
}

internal sealed class ObjectClass
{
    private HashSet<string>? _validAttributes;

    public string Name { get; }
    public HashSet<string> SuperTypes { get; }
    internal HashSet<string> SubTypes { get; }
    public HashSet<string> Must { get; }
    public HashSet<string> May { get; }

    public ObjectClass(
        string name,
        string[] superTypes,
        string[] must,
        string[] may)
    {
        Name = name;
        SuperTypes = superTypes.ToHashSet();
        SubTypes = new();
        Must = must.ToHashSet();
        May = may.ToHashSet();
    }

    public HashSet<string> GetValidAttributes(Dictionary<string, ObjectClass> registry)
    {
        if (_validAttributes == null)
        {
            HashSet<string> attributes = Must.Concat(May).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (string subType in SubTypes)
            {
                ObjectClass subClass = registry[subType];
                attributes.UnionWith(subClass.GetValidAttributes(registry));
            }
            _validAttributes = attributes.OrderBy(p => p).ToHashSet(StringComparer.OrdinalIgnoreCase);
        }

        return _validAttributes;
    }
}

internal sealed class SchemaMetadata
{
    private readonly Dictionary<string, AttributeTypeDescription> _typeInformation;
    private readonly Dictionary<string, ObjectClass> _classInformation = new();

    public SchemaMetadata(
        Dictionary<string, AttributeTypeDescription> typeInformation,
        Dictionary<string, DITContentRuleDescription> ditInformation,
        Dictionary<string, ObjectClassDescription> abstractClassInformation,
        Dictionary<string, ObjectClassDescription> auxClassInformation,
        Dictionary<string, ObjectClassDescription> structClassInformation)
    {
        _typeInformation = typeInformation;

        // process abstract classes as they can only inherit from each other.
        // top is special we want to process that one first as the rest will
        // inherit from it.
        if (abstractClassInformation.Remove("top", out ObjectClassDescription? topClass))
        {
            RegisterClassInformation(new[] { topClass });
        }
        RegisterClassInformation(abstractClassInformation.Values);

        // process auxiliary classes as they can inherit from abstract or other
        // auxiliary classes
        RegisterClassInformation(auxClassInformation.Values);

        // process structural classes at the end.
        RegisterClassInformation(structClassInformation.Values);

        // Add the auxiliary class mappings to each class and its sub types.
        foreach (DITContentRuleDescription auxRule in ditInformation.Values)
        {
            Queue<string> classQueue = new(new[] { auxRule.Names[0] });
            while (classQueue.Count > 0)
            {
                string className = classQueue.Dequeue();
                ObjectClass rawInfo = _classInformation[className];
                rawInfo.May.UnionWith(auxRule.May);
                rawInfo.Must.UnionWith(auxRule.Must);

                foreach (string subType in rawInfo.SubTypes)
                {
                    classQueue.Enqueue(subType);
                }
            }
        }

        // Used by argument completors.
        GlobalState.GetFromTLS().SchemaMetadata ??= this;
    }

    public void RegisterTransformer(string attribute, DefaultOverrider.CustomTransform transformer)
        => DefaultOverrider.Overrides[attribute] = transformer;

    public HashSet<string>? GetClassAttributesInformation(string name)
    {
        if (_classInformation.TryGetValue(name, out ObjectClass? classInfo))
        {
            return classInfo.GetValidAttributes(_classInformation);
        }
        else
        {
            return null;
        }
    }

    public (PSObject[], bool) TransformAttributeValue(string attribute, IList<byte[]> value, PSCmdlet? cmdlet)
    {
        AttributeTypeDescription? attrInfo = null;
        if (_typeInformation.ContainsKey(attribute))
            attrInfo = _typeInformation[attribute];

        // Default to DirectoryString for unknown attributes.
        string oidSyntax = attrInfo?.Syntax ?? "1.3.6.1.4.1.1466.115.121.1.15";

        DefaultOverrider.CustomTransform? customTransform = null;
        if (DefaultOverrider.Overrides.ContainsKey(attribute))
            customTransform = DefaultOverrider.Overrides[attribute];

        bool? isSingleValue = null;
        List<PSObject> processed = new();
        foreach (byte[] val in value)
        {
            PSObject parsed;
            try
            {
                object raw;
                if (customTransform != null)
                {
                    (raw, isSingleValue) = customTransform(attribute, val);
                }
                else
                {
                    raw = ProcessAttributeValue(oidSyntax, val);
                }

                parsed = PSObject.AsPSObject(raw);

            }
            catch (Exception e)
            {
                ErrorRecord rec = new(e, "AttributeParserError", ErrorCategory.ParserError, val);
                rec.ErrorDetails = new($"Failed to parse {attribute} (OID '{oidSyntax}') - {e.Message}");
                cmdlet?.WriteError(rec);

                parsed = new PSObject();
            }

            parsed.Properties.Add(new PSNoteProperty("RawValue", val));
            processed.Add(parsed);
        }

        return (processed.ToArray(), isSingleValue ?? attrInfo?.SingleValue ?? false);
    }

    internal static byte[][] ConvertToRawAttributeCollection(object? value)
    {
        if (value is null)
        {
            return Array.Empty<byte[]>();
        }
        else if (value is IEnumerable<byte> valueBytes)
        {
            return new byte[][]
            {
                valueBytes.ToArray(),
            };
        }
        else if (value is not string && value is IEnumerable valueEnumerable)
        {
            return valueEnumerable.Cast<object?>().Select(v => ConvertToRawAttributeValue(v)).ToArray();
        }
        else
        {
            return new byte[][]
            {
                ConvertToRawAttributeValue(value),
            };
        }
    }

    internal static byte[] ConvertToRawAttributeValue(object? value) => value switch
    {
        null => Array.Empty<byte>(),
        bool b => UTF8Bytes(b == true ? "TRUE" : "FALSE"),
        IEnumerable<byte> bytes => bytes.ToArray(),
        CommonSecurityDescriptor sd => sd.ToByteArray(),
        Enum e => UTF8Bytes(Convert.ChangeType(e, e.GetTypeCode()).ToString() ?? ""),
        DateTime dt => UTF8Bytes(dt.ToFileTimeUtc().ToString()),
        DateTimeOffset dto => UTF8Bytes(dto.UtcDateTime.ToFileTimeUtc().ToString()),
        Guid g => g.ToByteArray(),
        SecurityIdentifier sid => sid.ToByteArray(),
        TimeSpan ts => UTF8Bytes(ts.Ticks.ToString()),
        X509Certificate cert => cert.Export(X509ContentType.Cert),
        _ => UTF8Bytes(LanguagePrimitives.ConvertTo<string>(value)),
    };

    private void RegisterClassInformation(IEnumerable<ObjectClassDescription> classes)
    {
        Queue<ObjectClass> classQueue = new();
        foreach (ObjectClassDescription desc in classes)
        {
            string className = desc.Names[0];
            ObjectClass rawInfo = new(className, desc.SuperTypes, desc.Must, desc.May);

            bool ready = true;
            foreach (string superType in rawInfo.SuperTypes)
            {
                if (!_classInformation.ContainsKey(superType))
                {
                    ready = false;
                    break;
                }
            }

            if (ready)
            {
                foreach (string superType in rawInfo.SuperTypes)
                {
                    ObjectClass rawSuperType = _classInformation[superType];
                    rawInfo.Must.UnionWith(rawSuperType.Must);
                    rawInfo.May.UnionWith(rawSuperType.May);
                    rawSuperType.SubTypes.Add(className);
                }
                _classInformation[className] = rawInfo;
            }
            else
            {
                classQueue.Enqueue(rawInfo);
            }
        }

        HashSet<string> attempted = new();
        while (classQueue.Count > 0)
        {
            ObjectClass rawInfo = classQueue.Dequeue();
            if (!attempted.Add(rawInfo.Name))
            {
                throw new RuntimeException($"Found circular loop when attempting to process schema definition of '{rawInfo.Name}'");
            }

            bool ready = true;
            foreach (string superType in rawInfo.SuperTypes)
            {
                if (!_classInformation.ContainsKey(superType))
                {
                    ready = false;
                    break;
                }
            }

            if (ready)
            {
                foreach (string superType in rawInfo.SuperTypes)
                {
                    ObjectClass rawSuperType = _classInformation[superType];
                    rawInfo.Must.UnionWith(rawSuperType.Must);
                    rawInfo.May.UnionWith(rawSuperType.May);
                    rawSuperType.SubTypes.Add(rawInfo.Name);
                }
                // Now that we added one we can clear out the attempts and try again.
                _classInformation[rawInfo.Name] = rawInfo;
                attempted = new();
            }
            else
            {
                classQueue.Enqueue(rawInfo);
            }
        }
    }

    private static byte[] UTF8Bytes(string value) => Encoding.UTF8.GetBytes(value);

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
        "1.2.840.113556.1.4.907" => new CommonSecurityDescriptor(value), // Object-Security-Descriptor
        "1.2.840.113556.1.4.1221" => SyntaxDefinition.ReadDirectoryString(value), // CaseIgnoreString
        "1.2.840.113556.1.4.1362" => SyntaxDefinition.ReadDirectoryString(value), // CaseExactString
        "OctetString" => SyntaxDefinition.ReadOctetString(value), // Weird syntax but AD does send this

        _ => throw new NotImplementedException($"OID '{oid}' not recognised"),
    };
}
