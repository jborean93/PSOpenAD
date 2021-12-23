using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace PSOpenAD
{
    public class OpenADObject
    {
        internal static (string, bool)[] DEFAULT_PROPERTIES = new (string, bool)[] {
            ("distinguishedName", true),
            ("name", true),
            ("objectClass", true),
            ("objectGUID", true),
        };

        public string DistinguishedName { get; }
        public string Name { get; }
        public string ObjectClass { get; }
        public Guid ObjectGuid { get; }

        public OpenADObject(Dictionary<string, object?> attributes)
        {
            DistinguishedName = (string?)attributes.GetValueOrDefault("distinguishedName", null) ?? "";
            Name = (string?)attributes.GetValueOrDefault("name", null) ?? "";
            ObjectClass = ((object[]?)attributes["objectClass"] ?? new string[] { "" }).Cast<string>().Last();
            ObjectGuid = (Guid?)attributes.GetValueOrDefault("objectGUID", null) ?? Guid.Empty;
        }

        internal static (string, bool)[] ExtendPropertyList((string, bool)[] existing, (string, bool)[] toAdd)
        {
            List<(string, bool)> properties = existing.ToList();
            properties.AddRange(toAdd);
            return properties.ToArray();
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

        public OpenADPrincipal(Dictionary<string, object?> attributes) : base(attributes)
        {
            SamAccountName = (string?)attributes.GetValueOrDefault("sAMAccountName", null) ?? "";
            SID = (SecurityIdentifier?)attributes["objectSid"] ?? new SecurityIdentifier("");
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

        public OpenADAccount(Dictionary<string, object?> attributes) : base(attributes)
        {
            UserAccountControl control = (UserAccountControl?)attributes["userAccountControl"] ?? UserAccountControl.None;
            Enabled = (control & UserAccountControl.AccountDisable) == 0;
            UserPrincipalName = (string?)attributes.GetValueOrDefault("userPrincipalName", null) ?? "";
        }
    }

    public class OpenADComputer : OpenADAccount
    {
        internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
            OpenADAccount.DEFAULT_PROPERTIES, new (string, bool)[] {
                ("dNSHostName", true),
            });

        public string DNSHostName { get; }

        public OpenADComputer(Dictionary<string, object?> attributes) : base(attributes)
        {
            DNSHostName = (string?)attributes.GetValueOrDefault("dNSHostName", null) ?? "";
        }
    }

    public class OpenADServiceAccount : OpenADAccount
    {
        internal new static (string, bool)[] DEFAULT_PROPERTIES = ExtendPropertyList(
            OpenADAccount.DEFAULT_PROPERTIES, new (string, bool)[] {
                ("servicePrincipalName", true),
            });

        public string[] ServicePrincipalNames { get; }

        public OpenADServiceAccount(Dictionary<string, object?> attributes) : base(attributes)
        {
            ServicePrincipalNames = ((object[]?)attributes["servicePrincipalName"] ?? Array.Empty<string>()).
                Cast<string>()
                .ToArray();
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

        public OpenADUser(Dictionary<string, object?> attributes) : base(attributes)
        {
            GivenName = (string?)attributes.GetValueOrDefault("givenName", null) ?? "";
            Surname = (string?)attributes.GetValueOrDefault("sn", null) ?? "";
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

        public OpenADGroup(Dictionary<string, object?> attributes) : base(attributes)
        {
            GroupType grouptType = (GroupType?)attributes["groupType"] ?? GroupType.None;
            GroupCategory = (grouptType & GroupType.IsSecurity) != 0
                ? ADGroupCategory.Security : ADGroupCategory.Distribution;

            switch (grouptType)
            {
                case GroupType.DomainLocal:
                    GroupScope = ADGroupScope.DomainLocal;
                    break;
                case GroupType.Global:
                    GroupScope = ADGroupScope.Global;
                    break;
                default:
                    GroupScope = ADGroupScope.Universal;
                    break;
            }
        }
    }

    public sealed class SecurityIdentifier
    {
        private readonly byte _revision;
        private readonly UInt64 _identifierAuthority;
        private readonly uint[] _subAuthorities;

        public int BinaryLength => 8 + (_subAuthorities.Length * 4);

        public string Value => ToString();

        public SecurityIdentifier(string sid)
        {
            Match m = Regex.Match(sid, @"^S-(?<revision>\d)-(?<authority>\d+)(?:-\d+){1,15}$");
            if (m.Success)
            {
                _revision = byte.Parse(m.Groups["revision"].Value);
                _identifierAuthority = UInt64.Parse(m.Groups["authority"].Value);
                string[] sidSplit = sid.Split('-');

                _subAuthorities = new uint[sidSplit.Length - 3];
                for (int i = 3; i < sidSplit.Length; i++)
                {
                    _subAuthorities[i - 3] = uint.Parse(sidSplit[i]);
                }
            }
            else
            {
                throw new ArgumentException(nameof(sid));
            }
        }

        public SecurityIdentifier(byte[] binaryForm, int offset)
        {
            _revision = binaryForm[offset];

            byte[] rawAuthority = new byte[8];
            Array.Copy(binaryForm, offset + 2, rawAuthority, 2, 6);
            Array.Reverse(rawAuthority);
            _identifierAuthority = BitConverter.ToUInt64(rawAuthority);

            _subAuthorities = new uint[binaryForm[offset + 1]];
            for (int i = 0; i < _subAuthorities.Length; i++)
            {
                byte[] idBytes = new byte[4];
                Array.Copy(binaryForm, offset + 8 + (i * 4), idBytes, 0, idBytes.Length);
                _subAuthorities[i] = BitConverter.ToUInt32(idBytes);
            }
        }

        public void GetBinaryForm(byte[] binaryForm, int offset)
        {
            binaryForm[offset] = _revision;
            binaryForm[offset + 1] = (byte)_subAuthorities.Length;

            byte[] authority = BitConverter.GetBytes(_identifierAuthority);
            Array.Reverse(authority);
            Array.Copy(authority, 2, binaryForm, offset + 2, 6);

            for (int i = 0; i < _subAuthorities.Length; i++)
            {
                byte[] rawRid = BitConverter.GetBytes(_subAuthorities[i]);
                Array.Copy(rawRid, 0, binaryForm, offset + 8 + (i * 4), rawRid.Length);
            }
        }

        public override string ToString() => $"S-{_revision}-{_identifierAuthority}-" + String.Join("-", _subAuthorities);
    }

    public enum SearchScope
    {
        Base,
        OneLevel,
        Subtree,
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
}
