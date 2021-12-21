using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Commands
{
    public abstract class GetOpenADOperation : PSCmdlet
    {
        internal string _ldapFilter = "";

        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "LDAPFilter"
        )]
        public string LDAPFilter { get => _ldapFilter; set => _ldapFilter = value; }

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true
        )]
        public OpenADSession Session { get; set; } = null!;

        [Parameter()]
        [Alias("Properties")]
        [ValidateNotNullOrEmpty]
        public string[]? Property { get; set; }

        [Parameter()]
        public string? SearchBase { get; set; }

        [Parameter()]
        public SearchScope SearchScope { get; set; } = SearchScope.Subtree;

        [Parameter()]
        public SwitchParameter IncludeDeletedObjects { get; set; }

        internal abstract (string, bool)[] DefaultProperties { get; }

        internal abstract OpenADObject CreateADObject(Dictionary<string, object?> attributes);

        protected override void ProcessRecord()
        {
            string searchBase = SearchBase ?? Session.DefaultNamingContext;
            LDAPSearchScope ldapScope = (LDAPSearchScope)SearchScope;

            HashSet<string> requestedProperties = DefaultProperties.Select(p => p.Item1).ToHashSet();
            string[] explicitProperties = Property ?? Array.Empty<string>();
            foreach (string prop in explicitProperties)
                requestedProperties.Add(prop);

            int msgid = OpenLDAP.SearchExt(Session.Handle, searchBase, ldapScope, _ldapFilter,
                requestedProperties.ToArray(), false);
            SafeLdapMessage res = OpenLDAP.Result(Session.Handle, msgid, LDAPMessageCount.LDAP_MSG_ALL);
            foreach (IntPtr entry in OpenLDAP.GetEntries(Session.Handle, res))
            {
                Dictionary<string, object?> props = new Dictionary<string, object?>();
                foreach (string attribute in OpenLDAP.GetAttributes(Session.Handle, entry))
                {
                    byte[][] rawValues = OpenLDAP.GetValues(Session.Handle, entry, attribute).ToArray();
                    props[attribute] = Session.AttributeTransformer.Transform(attribute, rawValues);
                }

                OpenADObject adObj = CreateADObject(props);

                // This adds a note property for each explicitly requested property, excluding the ones the object
                // naturally exposes.
                PSObject adPSObj = PSObject.AsPSObject(adObj);
                props.Keys
                    .Where(v => explicitProperties.Contains(v) && !DefaultProperties.Contains((v, true)))
                    .OrderBy(v => v)
                    .ToList()
                    .ForEach(v => adPSObj.Properties.Add(new PSNoteProperty(v, props[v])));

                WriteObject(adObj);
            }
        }
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADObject",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADObject))]
    public class GetOpenADObject : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Identity"
        )]
        public ADObjectIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        internal override (string, bool)[] DefaultProperties => OpenADObject.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADObject(attributes);
    }


    [Cmdlet(
        VerbsCommon.Get, "OpenADComputer",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADComputer))]
    public class GetOpenADComputer : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Identity"
        )]
        public ADPrincipalIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        internal override (string, bool)[] DefaultProperties => OpenADComputer.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADComputer(attributes);
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADUser",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADUser))]
    public class GetOpenADUser : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Identity"
        )]
        public ADPrincipalIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        internal override (string, bool)[] DefaultProperties => OpenADUser.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADUser(attributes);
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADGroup",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADGroup))]
    public class GetOpenADGroup : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Identity"
        )]
        public ADPrincipalIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        internal override (string, bool)[] DefaultProperties => OpenADGroup.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADGroup(attributes);
    }
}
