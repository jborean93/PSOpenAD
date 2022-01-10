using PSOpenAD.LDAP;
using System;
using System.Text.RegularExpressions;

namespace PSOpenAD
{
    public class ADObjectIdentity
    {
        internal LDAPFilter LDAPFilter { get; set; }

        internal ADObjectIdentity() => LDAPFilter = new FilterPresent("objectClass");

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

        internal bool TryParseGuid(string value, out LDAPFilter filter)
        {
            filter = new FilterPresent("");

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

        internal bool TryParseDN(string value, out LDAPFilter filter)
        {
            filter = new FilterPresent("");

            if (Regex.Match(value, "^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$").Success)
            {
                filter = new FilterEquality("distinguishedName", LDAPFilter.ParseFilterValue(value));
                return true;
            }
            else
            {
                return false;
            }
        }

        internal LDAPFilter ObjectGUIDFilter(Guid objectGuid)
        {
            return new FilterEquality("objectGUID", objectGuid.ToByteArray());
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

        internal bool TryParseUPN(string value, out LDAPFilter filter)
        {
            filter = new FilterPresent("");

            if (Regex.Match(value, @"^.*\@.*\..*$").Success)
            {
                filter = new FilterEquality("userPrincipalName", LDAPFilter.ParseFilterValue(value));
                return true;
            }
            else
            {
                return false;
            }
        }

        internal bool TryParseSamAccountName(string value, out LDAPFilter filter)
        {
            filter = new FilterPresent("");

            Match m = Regex.Match(value, @"^(?:[^:*?""<>|\/\\]+\\)?(?<username>[^;:""<>|?,=\*\+\\\(\)]{1,20})$");
            if (m.Success)
            {
                string username = m.Groups["username"].Value;
                filter = new FilterEquality("sAMAccountName", LDAPFilter.ParseFilterValue(username));
                return true;
            }
            else
            {
                return false;
            }
        }

        internal bool TryParseSecurityIdentifier(string value, out LDAPFilter filter)
        {
            filter = new FilterPresent("");

            try
            {
                SecurityIdentifier sid = new SecurityIdentifier(value);
                filter = ObjectSidFilter(sid);
                return true;
            }
            catch (ArgumentException) { }

            return false;
        }

        internal LDAPFilter ObjectSidFilter(SecurityIdentifier sid)
        {
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);
            return new FilterEquality("objectSid", sidBytes);
        }
    }
}
