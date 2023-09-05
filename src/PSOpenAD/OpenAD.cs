using PSOpenAD.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD;

public class OpenADEntity
{
    internal static (string, bool)[] DEFAULT_PROPERTIES = Array.Empty<(string, bool)>();

    public OpenADEntity(IDictionary<string, (PSObject[], bool)> attributes)
    {}

    internal static (string, bool)[] ExtendPropertyList((string, bool)[] existing, (string, bool)[] toAdd)
    {
        List<(string, bool)> properties = existing.ToList();
        properties.AddRange(toAdd);
        return properties.ToArray();
    }
}

public class OpenADObject : OpenADEntity
{
    internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
        OpenADEntity.DEFAULT_PROPERTIES, new (string, bool)[] {
            ("distinguishedName", true),
            ("name", true),
            ("objectClass", true),
            ("objectGUID", true),
        });

    public string DistinguishedName { get; }
    public string Name { get; }
    public string ObjectClass { get; }
    public Guid ObjectGuid { get; }

    public OpenADObject(IDictionary<string, (PSObject[], bool)> attributes)
        : base(attributes)
    {
        DistinguishedName = attributes.ContainsKey("distinguishedName")
            ? (string)attributes["distinguishedName"].Item1[0].BaseObject
            : "";
        Name = attributes.ContainsKey("name")
            ? (string)attributes["name"].Item1[0].BaseObject
            : "";

        ObjectClass = attributes.ContainsKey("objectClass")
            ? (string)attributes["objectClass"].Item1.Last().BaseObject
            : "";

        ObjectGuid = attributes.ContainsKey("objectGUID")
            ? (Guid)attributes["objectGUID"].Item1[0].BaseObject
            : Guid.Empty;
    }
}

public class OpenADPrincipal : OpenADObject
{
    internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
        OpenADObject.DEFAULT_PROPERTIES, new (string, bool)[] {
            ("sAMAccountName", true),
            ("objectSid", false),
        });

    public string SamAccountName { get; }
    public SecurityIdentifier SID { get; }

    public OpenADPrincipal(IDictionary<string, (PSObject[], bool)> attributes) : base(attributes)
    {
        SamAccountName = attributes.ContainsKey("sAMAccountName")
            ? (string)attributes["sAMAccountName"].Item1[0].BaseObject
            : "";

        SID = attributes.ContainsKey("objectSid")
            ? (SecurityIdentifier)attributes["objectSid"].Item1[0].BaseObject
            : new SecurityIdentifier("");
    }
}

public class OpenADAccount : OpenADPrincipal
{
    internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
        OpenADPrincipal.DEFAULT_PROPERTIES, new (string, bool)[] {
            ("userAccountControl", false),
            ("userPrincipalName", true),
        });

    public bool Enabled { get; }

    public string UserPrincipalName { get; }

    public OpenADAccount(IDictionary<string, (PSObject[], bool)> attributes) : base(attributes)
    {
        UserAccountControl control = attributes.ContainsKey("userAccountControl")
            ? (UserAccountControl)attributes["userAccountControl"].Item1[0].BaseObject
            : UserAccountControl.None;

        Enabled = (control & UserAccountControl.AccountDisable) == 0;
        UserPrincipalName = attributes.ContainsKey("userPrincipalName")
            ? (string)attributes["userPrincipalName"].Item1[0].BaseObject
            : "";
    }
}

public class OpenADComputer : OpenADAccount
{
    internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
        OpenADAccount.DEFAULT_PROPERTIES, new (string, bool)[] {
            ("dNSHostName", true),
        });

    public string DNSHostName { get; }

    public OpenADComputer(IDictionary<string, (PSObject[], bool)> attributes) : base(attributes)
    {
        DNSHostName = attributes.ContainsKey("dNSHostName")
            ? (string)attributes["dNSHostName"].Item1[0].BaseObject
            : "";
    }
}

public class OpenADServiceAccount : OpenADAccount
{
    internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
        OpenADAccount.DEFAULT_PROPERTIES, new (string, bool)[] {
            ("servicePrincipalName", true),
        });

    public string[] ServicePrincipalNames { get; }

    public OpenADServiceAccount(IDictionary<string, (PSObject[], bool)> attributes) : base(attributes)
    {
        ServicePrincipalNames = attributes.ContainsKey("servicePrincipalName")
            ? attributes["servicePrincipalName"].Item1.Select(v => (string)v.BaseObject).ToArray()
            : Array.Empty<string>();
    }
}

public class OpenADUser : OpenADAccount
{
    internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
        OpenADAccount.DEFAULT_PROPERTIES, new (string, bool)[] {
            ("givenName", true),
            ("sn", false),
        });

    public string GivenName { get; }
    public string Surname { get; }

    public OpenADUser(IDictionary<string, (PSObject[], bool)> attributes) : base(attributes)
    {
        GivenName = attributes.ContainsKey("givenName")
            ? (string)attributes["givenName"].Item1[0].BaseObject
            : "";

        Surname = attributes.ContainsKey("sn")
            ? (string)attributes["sn"].Item1[0].BaseObject
            : "";
    }
}

public class OpenADGroup : OpenADPrincipal
{
    internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
        OpenADPrincipal.DEFAULT_PROPERTIES, new (string, bool)[] {
            ("groupType", false),
        });

    public ADGroupCategory GroupCategory { get; }

    public ADGroupScope GroupScope { get; }

    public OpenADGroup(IDictionary<string, (PSObject[], bool)> attributes) : base(attributes)
    {
        GroupType groupType = attributes.ContainsKey("groupType")
            ? (GroupType)attributes["groupType"].Item1[0].BaseObject
            : GroupType.None;

        GroupCategory = (groupType & GroupType.IsSecurity) != 0
            ? ADGroupCategory.Security : ADGroupCategory.Distribution;

        GroupScope = groupType switch
        {
            GroupType.DomainLocal => ADGroupScope.DomainLocal,
            GroupType.Global => ADGroupScope.Global,
            _ => ADGroupScope.Universal,
        };
    }
}

[Flags]
public enum SupportedEncryptionTypes
{
    None = 0x00,
    DesCbcCrc = 0x01,
    DesCbcMd5 = 0x02,
    Rc4Hmac = 0x04,
    Aes128CtsHmacSha196 = 0x08,
    Aes256CtsHmacSha196 = 0x10,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6dab41f1-e379-4404-a12e-30135b711729
public enum ADDomainControllerMode
{
    Unknown = -1,
    Windows2000,
    Windows2003 = 2,
    Windows2008,
    Windows2008R2,
    Windows2012,
    Windows2012R2,
    Windows2016,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6dd88965-8feb-4369-ae7e-075985da8071
public enum ADDomainMode
{
    UnknownDomain = -1,
    Windows2000Domain,
    Windows2003InterimDomain,
    Windows2003Domain,
    Windows2008Domain,
    Windows2008R2Domain,
    Windows2012Domain,
    Windows2012R2Domain,
    Windows2016Domain,
}

public enum ADGroupCategory
{
    Distribution,
    Security,
}

public enum ADGroupScope
{
    DomainLocal,
    Global,
    Universal,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d49624d0-9320-4368-8b0c-a7998ac2abdb
public enum ADForestMode
{
    UnknownForest = -1,
    Windows2000Forest,
    Windows2003InterimForest,
    Windows2003Forest,
    Windows2008Forest,
    Windows2008R2Forest,
    Windows2012Forest,
    Windows2012R2Forest,
    Windows2016Forest,
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/11972272-09ec-4a42-bf5e-3e99b321cf55
[Flags]
public enum GroupType : uint
{
    None = 0x00000000,
    System = 0x00000001,
    Global = 0x00000002,
    DomainLocal = 0x00000004,
    Universal = 0x00000008,
    AppBasic = 0x00000010,
    AppQuery = 0x00000020,
    IsSecurity = 0x80000000,
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-ada1/3c95bace-a9bd-4227-9c32-de1015d2bcd2
[Flags]
public enum InstanceType
{
    None = 0x0000000,
    HeadOfNamingContext = 0x00000001,
    ReplicaNotInstantiated = 0x00000002,
    IsWritableOnDirectory = 0x00000004,
    NamingContextAboveIsHeld = 0x00000008,
    NamingContextBeingConstructed = 0x00000010,
    NamingContextBeingRemoved = 0x00000020,
}

// https://docs.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information
[Flags]
public enum PasswordProperties
{
    /// <summary>
    /// <para>
    /// The password must have a mix of at least two of the following types of characters:
    ///     * Uppercase characters
    ///     * Lowercase characters
    ///     * Numerals
    /// </para>
    /// <para>
    /// DOMAIN_PASSWORD_COMPLEX
    /// </para>
    /// </summary>
    Complex = 0x00000001,

    /// <summary>
    /// <para>
    /// The password cannot be changed without logging on. Otherwise, if your password has expired, you can change
    /// your password and then log on.
    /// </para>
    /// <para>
    /// DOMAIN_PASSWORD_NO_ANON_CHANGE
    /// </summary>
    NoAnonymousChange = 0x00000002,

    /// <summary>
    /// <para>
    /// Forces the client to use a protocol that does not allow the domain controller to get the plaintext
    /// password.
    /// </para>
    /// <para>
    /// DOMAIN_PASSWORD_NO_CLEAR_CHANGE
    /// </summary>
    NoClearChange = 0x00000004,

    /// <summary>
    /// <para>
    /// Allows the built-in administrator account to be locked out from network logons.
    /// </para>
    /// <para>
    /// DOMAIN_LOCKOUT_ADMINS
    /// </summary>
    LockoutAdmins = 0x00000008,

    /// <summary>
    /// The directory service is storing a plaintext password for all users instead of a hash function of the
    /// password.
    /// </para>
    /// <para>
    /// DOMAIN_PASSWORD_STORE_CLEARTEXT
    /// </summary>
    StoreCleartext = 0x00000010,

    /// <summary>
    /// <para>
    /// Removes the requirement that the machine account password be automatically changed every week. This value
    /// should not be used as it can weaken security.
    /// </para>
    /// <para>
    /// DOMAIN_REFUSE_PASSWORD_CHANGE
    /// </summary>
    RefusePasswordChange = 0x00000020,
}

public enum SAMAccountType
{
    DomainObject = 0x0000000,
    GroupObject = 0x10000000,
    NonSecurityGroupObject = 0x10000001,
    AliasObject = 0x20000000,
    NonSecurityAliasObject = 0x20000001,
    UserObject = 0x30000000,
    MachineObject = 0x30000001,
    TrustAccount = 0x30000002,
    AppBasicGroup = 0x40000000,
    AppQueryGroup = 0x40000001,
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1e38247d-8234-4273-9de3-bbf313548631
[Flags]
public enum SystemFlags : uint
{
    None = 0x00000000,

    /// <summary>
    /// When used on an attributeSchema object, it specifies that this attribute is not replicated. If it is used
    /// on a crossRef object, it specifies that the NC that the crossRef is for is an Active Directory NC.
    /// FLAG_ATTR_NOT_REPLICATED - FLAG_CR_NTDS_NC
    /// </summary>
    NotReplicated = 0x00000001,

    /// <summary>
    /// When used on an attributeSchema object, it specifies that the attribute is a member of a partial attribute
    /// set (PAS). If used on a crossRef object, it specifies that the NC is a domain NC.
    /// FLAG_ATTR_REQ_PARTIAL_SET_MEMBER - FLAG_CR_NTDS_DOMAIN
    /// </summary>
    PartialAttributeSet = 0x00000002,

    /// <summary>
    /// When used on an attributeSchema object, this flag specifies that the attribute is a constructed attribute.
    /// If used on a crossRef object, it specifies that the NC is not to be replicated to GCs.
    /// FLAG_ATTR_IS_CONSTRUCTED - FLAG_CR_NTDS_NOT_GC_REPLICATED
    /// </summary>
    AttributeIsConstructed = 0x00000004,

    /// <summary>
    /// Only used on an attributeSchema object. It specifies that the attribute is an operational attribute.
    /// FLAG_ATTR_IS_OPERATIONAL
    /// </summary>
    AttributeIsOperational = 0x00000008,

    /// <summary>
    /// Only used on attributeSchema and classSchema objects. It specifies that this attribute or class is part of
    /// the base schema. Modifications to base schema objects are specially restricted.
    /// FLAG_SCHEMA_BASE_OBJECT
    /// </summary>
    SchemaBaseObject = 0x00000010,

    /// <summary>
    /// Only used on an attributeSchema object. It specifies that this attribute can be used as an RDN attribute.
    /// FLAG_ATTR_IS_RDN
    /// </summary>
    AttributeIsRDN = 0x00000020,

    /// <summary>
    /// Specifies that the object does not move to the Deleted Objects container when the object is deleted.
    /// FLAG_DISALLOW_MOVE_ON_DELETE
    /// </summary>
    DisallowMoveOnDelete = 0x02000000,

    /// <summary>
    /// Specifies that if the object is in a domain NC, the object cannot be moved.
    /// FLAG_DOMAIN_DISALLOW_MOVE
    /// </summary>
    DomainDisallowMove = 0x04000000,

    /// <summary>
    /// Specifies that if the object is in a domain NC, the object cannot be renamed.
    /// FLAG_DOMAIN_DISALLOW_RENAME
    /// </summary>
    DomainDisallowRename = 0x08000000,

    /// <summary>
    /// Specifies that if the object is in the config NC, the object can be moved, with restrictions.
    /// FLAG_CONFIG_ALLOW_LIMITED_MOVE
    /// </summary>
    ConfigAllowLimitedMove = 0x10000000,

    /// <summary>
    /// Specifies that if the object is in the config NC, the object can be moved.
    /// FLAG_CONFIG_ALLOW_MOVE
    /// </summary>
    ConfigAllowMove = 0x20000000,

    /// <summary>
    /// Specifies that if the object is in the config NC, the object can be renamed.
    /// FLAG_CONFIG_ALLOW_RENAME
    /// </summary>
    ConfigAllowRename = 0x40000000,

    /// <summary>
    /// Specifies that the object cannot be deleted.
    /// FLAG_DISALLOW_DELETE
    /// </summary>
    DisallowDelete = 0x80000000,
}

[Flags]
public enum UserAccountControl : uint
{
    None = 0x00000000,
    Script = 0x00000001,
    AccountDisable = 0x00000002,
    HomeDirectoryRequired = 0x00000008,
    Lockout = 0x00000010,
    PasswordNotRequired = 0x00000020,
    PasswordCannotChange = 0x00000040,
    EncryptedTextPasswordAllowed = 0x00000080,
    TemporaryDuplicateAccount = 0x00000100,
    NormalAccount = 0x00000200,
    InterdomainTrustAccount = 0x00000800,
    WorkstationTrustAccount = 0x00001000,
    ServerTrustAccount = 0x00002000,
    DontExpirePassword = 0x00010000,
    MNSLogonAccount = 0x00020000,
    SmartcardRequired = 0x00040000,
    TrustedForDelegation = 0x00080000,
    NotDelegated = 0x00100000,
    UseDESKeyOnly = 0x00200000,
    DontRequirePreAuth = 0x00400000,
    PasswordExpired = 0x00800000,
    TrustedToAuthenticateForDelegation = 0x01000000,
    PartialSecretsAccount = 0x04000000,
}
