using System;
using System.Text.RegularExpressions;

namespace PSOpenAD
{
    public class ADObjectIdentity
    {
        public string LDAPFilter { get; internal set; }

        internal ADObjectIdentity() => LDAPFilter = "";

        public ADObjectIdentity(string value)
        {
            if (TryParseGuid(value, out var filter))
                LDAPFilter = filter;
            else if (TryParseDN(value, out filter))
                LDAPFilter = filter;
            else
                throw new ArgumentException(nameof(value));
        }

        public ADObjectIdentity(OpenADObject obj) : this(obj.ObjectGuid) { }

        public ADObjectIdentity(Guid objectGuid) => LDAPFilter = ObjectGUIDFilter(objectGuid);

        internal bool TryParseGuid(string value, out string filter)
        {
            filter = "";

            if (Guid.TryParse(value, out var guid))
            {
                filter = ObjectGUIDFilter(guid);
                return true;
            }
            else
            {
                return false;
            }
        }

        internal bool TryParseDN(string value, out string filter)
        {
            filter = "";

            if (Regex.Match(value, @"^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$").Success)
            {
                filter = $"(distinguishedName={value})";
                return true;
            }
            else
            {
                return false;
            }
        }

        internal string ObjectGUIDFilter(Guid objectGuid)
        {
            byte[] guidBytes = objectGuid.ToByteArray();
            string escapedHex = BitConverter.ToString(guidBytes).Replace("-", "\\");

            return String.Format("(objectGUID=\\{0})", escapedHex);
        }
    }

    public class ADPrincipalIdentity : ADObjectIdentity
    {
        public ADPrincipalIdentity(string value)
        {
            if (TryParseGuid(value, out var filter))
                LDAPFilter = filter;
            else if (TryParseDN(value, out filter))
                LDAPFilter = filter;
            else if (TryParseUPN(value, out filter))
                LDAPFilter = filter;
            else if (TryParseSamAccountName(value, out filter))
                LDAPFilter = filter;
            else if (TryParseSecurityIdentifier(value, out filter))
                LDAPFilter = filter;
            else
                throw new ArgumentException(nameof(value));
        }

        public ADPrincipalIdentity(SecurityIdentifier sid) => LDAPFilter = ObjectSidFilter(sid);

        public ADPrincipalIdentity(OpenADObject obj) : base(obj) { }

        public ADPrincipalIdentity(Guid objectGuid) : base(objectGuid) { }

        internal bool TryParseUPN(string value, out string filter)
        {
            filter = "";

            if (Regex.Match(value, @"^.*\@.*\..*$").Success)
            {
                filter = $"(userPrincipalName={value})";
                return true;
            }
            else
            {
                return false;
            }
        }

        internal bool TryParseSamAccountName(string value, out string filter)
        {
            filter = "";

            Match m = Regex.Match(value, @"^(?:[^:*?""<>|\/\\]+\\)?(?<username>[^;:""<>|?,=\*\+\\\(\)]{1,20})$");
            if (m.Success)
            {
                string username = m.Groups["username"].Value;
                filter = $"(sAMAccountName={username})";
                return true;
            }
            else
            {
                return false;
            }
        }

        internal bool TryParseSecurityIdentifier(string value, out string filter)
        {
            filter = "";

            try
            {
                SecurityIdentifier sid = new SecurityIdentifier(value);
                filter = ObjectSidFilter(sid);
                return true;
            }
            catch (ArgumentException) { }

            return false;
        }

        internal string ObjectSidFilter(SecurityIdentifier sid)
        {
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            string escapedHex = BitConverter.ToString(sidBytes).Replace("-", "\\");

            return String.Format("(objectSid=\\{0})", escapedHex);
        }
    }
}
