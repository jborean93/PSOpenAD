using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PSOpenAD
{
    public class OpenADObject
    {
        internal static string[] DEFAULT_PROPERTIES = new string[] { "distinguishedName", "name", "objectClass",
            "objectGUID" };

        public string DistinguishedName { get => (string)Properties["distinguishedName"]; }
        public string Name { get => (string)Properties["name"]; }
        public string ObjectClass { get => (string)((object[])Properties["objectClass"]).Last(); }
        public Guid ObjectGuid { get => new Guid((byte[])Properties["objectGUID"]); }
        public Dictionary<string, object> Properties { get; }

        public OpenADObject(Dictionary<string, object> properties)
        {
            Properties = properties;
        }
    }

    public sealed class SecurityIdentifier
    {
        public string Value { get; }

        public SecurityIdentifier(byte[] sid)
        {
            byte[] rawAuthority = new byte[8];
            Array.Copy(sid, 2, rawAuthority, 2, 6);
            Array.Reverse(rawAuthority);
            UInt64 authority = BitConverter.ToUInt64(rawAuthority);

            StringBuilder sidValue = new StringBuilder($"S-{sid[0]}-{authority}");
            for (int i = 0; i < sid[1]; i++)
            {
                byte[] idBytes = new byte[4];
                Array.Copy(sid, 8 + (i * 4), idBytes, 0, 4);
                uint id = BitConverter.ToUInt32(idBytes);
                sidValue.Append($"-{id}");
            }
            Value = sidValue.ToString();
        }

        public override string ToString() => Value;
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
