using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Text;

namespace PSOpenAD.Commands
{
    public enum SearchScope
    {
        Base,
        OneLevel,
        Subtree,
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADObject",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADObject))]
    public class GetOpenADObject : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Identity"
        )]
        public string Identity { get; set; } = "";

        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "LDAPFilter"
        )]
        public string? LDAPFilter { get; set; }

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true
        )]
        public OpenADSession Session { get; set; } = null!;

        [Parameter()]
        [ValidateNotNullOrEmpty]
        public string[]? Property { get; set; }

        [Parameter()]
        public string? SearchBase { get; set; }

        [Parameter()]
        public SearchScope SearchScope { get; set; } = SearchScope.Subtree;


        [Parameter()]
        public SwitchParameter IncludeDeletedObjects { get; set; }

        protected override void ProcessRecord()
        {
            string searchBase = SearchBase ?? Session.DefaultNamingContext;
            LDAPSearchScope ldapScope = (LDAPSearchScope)SearchScope;

            if (ParameterSetName == "Identity")
            {
                if (Guid.TryParse(Identity, out var identityGuid))
                {
                    byte[] guidBytes = identityGuid.ToByteArray();
                    string escapedHex = BitConverter.ToString(guidBytes).Replace("-", "\\");
                    LDAPFilter = String.Format("(objectGUID=\\{0})", escapedHex);
                }
                else
                {
                    LDAPFilter = $"(distinguishedName={Identity})";
                }
            }

            int msgid = OpenLDAP.SearchExt(Session.Handle, searchBase, ldapScope, LDAPFilter, Property, false);
            SafeLdapMessage res = OpenLDAP.Result(Session.Handle, msgid, LDAPMessageCount.LDAP_MSG_ALL);
            foreach (IntPtr entry in OpenLDAP.GetEntries(Session.Handle, res))
            {
                Dictionary<string, object> props = new Dictionary<string, object>();
                foreach (string attribute in OpenLDAP.GetAttributes(Session.Handle, entry))
                {
                    AttributeTypes? attrInfo = Session.AttributeTypes.GetValueOrDefault(attribute, null);
                    object[] values = OpenLDAP.GetValues(Session.Handle, entry, attribute).Select(
                        v => ParseEntryValue(attrInfo, v)).ToArray();

                    props[attribute] = attrInfo?.SingleValue == true ? values[0] : values;
                }

                OpenADObject adObj = new OpenADObject(props);

                // This adds a script property on the main object to the actual property value as a nice shorthand.
                // Should this continue to happen, should there be a mapping of known raw types to a structured value
                // that takes precedence as well?
                string[] filterList = new string[] { "distinguishedName", "name", "objectClass", "objectGUID" };
                foreach (string key in props.Keys.Where(v => !filterList.Contains(v)).OrderBy(v => v))
                {
                    string safeKey = CodeGeneration.EscapeSingleQuotedStringContent(key);
                    PSObject.AsPSObject(adObj).Properties.Add(new PSScriptProperty(key,
                        ScriptBlock.Create($"$this.Properties['{safeKey}']")));
                }

                WriteObject(adObj);
            }
        }

        private object ParseEntryValue(AttributeTypes? attrInfo, byte[] value) => attrInfo?.Syntax switch
        {
            "1.2.840.113556.1.4.903" => throw new NotImplementedException("DNWithOctetString"),
            "1.2.840.113556.1.4.904" => throw new NotImplementedException("DNWithString"),
            "1.2.840.113556.1.4.905" => throw new NotImplementedException("Telex"),
            "1.2.840.113556.1.4.906" => Int64.Parse(ParseStringValue(value)), // INTEGER8
            "1.2.840.113556.1.4.907" => throw new NotImplementedException("ObjectSecurityDescriptor"),
            "1.3.6.1.4.1.1466.115.121.1.7" => ParseStringValue(value) == "TRUE", // Boolean
            "1.3.6.1.4.1.1466.115.121.1.12" => ParseStringValue(value), // DN
            "1.3.6.1.4.1.1466.115.121.1.15" => ParseStringValue(value), // DirectoryString
            "1.3.6.1.4.1.1466.115.121.1.24" => ParseDateTimeValue(value), // GeneralizedTime
            "1.3.6.1.4.1.1466.115.121.1.26" => throw new NotImplementedException("IA5String"),
            "1.3.6.1.4.1.1466.115.121.1.27" => Int32.Parse(ParseStringValue(value)), // INTEGER
            "1.3.6.1.4.1.1466.115.121.1.36" => throw new NotImplementedException("NumericString"),
            "1.3.6.1.4.1.1466.115.121.1.38" => ParseStringValue(value), // OID
            "1.3.6.1.4.1.1466.115.121.1.40" => value, // OctetString
            "1.3.6.1.4.1.1466.115.121.1.43" => throw new NotImplementedException("PresentationAddress"),
            "1.3.6.1.4.1.1466.115.121.1.44" => throw new NotImplementedException("PrintableString"),
            "1.3.6.1.4.1.1466.115.121.1.53" => throw new NotImplementedException("UTCTime"),
            _ => ParseStringValue(value),
        };

        private static DateTime ParseDateTimeValue(byte[] value)
        {
            // Needs to be expanded to support https://ldapwiki.com/wiki/GeneralizedTime
            string rawDT = ParseStringValue(value);
            return DateTime.ParseExact(rawDT, "yyyyMMddHHmmss.fK", CultureInfo.InvariantCulture);
        }

        private static string ParseStringValue(byte[] value) => Encoding.UTF8.GetString(value);
    }
}
