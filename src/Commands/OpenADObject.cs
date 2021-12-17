using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Management.Automation;
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

            int msgid = OpenLDAP.SearchExt(Session.Handle, searchBase, ldapScope, LDAPFilter, Property, false);
            SafeLdapMessage res = OpenLDAP.Result(Session.Handle, msgid, LDAPMessageCount.LDAP_MSG_ALL);
            foreach (IntPtr entry in OpenLDAP.GetEntries(Session.Handle, res))
            {
                foreach (string attribute in OpenLDAP.GetAttributes(Session.Handle, entry))
                {
                    List<string> values = new List<string>();
                    foreach (byte[] value in OpenLDAP.GetValues(Session.Handle, entry, attribute))
                    {
                        values.Add(Encoding.UTF8.GetString(value));
                    }

                    WriteObject(new OpenADProperty()
                    {
                        Name = attribute,
                        Value = values.ToArray(),
                    });
                }
            }
        }
    }

    public class OpenADProperty
    {
        public string Name { get; internal set; } = "";
        public string[] Value { get; internal set; } = Array.Empty<string>();
    }
}
