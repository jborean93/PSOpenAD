using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Commands
{
    public abstract class GetOpenADOperation : PSCmdlet
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

        internal abstract string ParseIdentityToFilter(string identity);

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
                    LDAPFilter = ParseIdentityToFilter(Identity);
                }
            }

            HashSet<string> requestedProperties = DefaultProperties.Select(p => p.Item1).ToHashSet();
            foreach (string prop in Property ?? Array.Empty<string>())
                requestedProperties.Add(prop);

            int msgid = OpenLDAP.SearchExt(Session.Handle, searchBase, ldapScope, LDAPFilter,
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

                // This adds a script property on the main object to the actual property value as a nice shorthand.
                // Should this continue to happen, should there be a mapping of known raw types to a structured value
                // that takes precedence as well?
                PSObject adPSObj = PSObject.AsPSObject(adObj);
                props.Keys
                    .Where(v => !DefaultProperties.Contains((v, true)))
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
        internal override (string, bool)[] DefaultProperties => OpenADObject.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADObject(attributes);

        internal override string ParseIdentityToFilter(string identity) => $"(distinguishedName={Identity})";
    }


    [Cmdlet(
        VerbsCommon.Get, "OpenADComputer",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADComputer))]
    public class GetOpenADComputer : GetOpenADOperation
    {
        internal override (string, bool)[] DefaultProperties => OpenADComputer.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADComputer(attributes);

        internal override string ParseIdentityToFilter(string identity) => $"(distinguishedName={Identity})";
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADUser",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADUser))]
    public class GetOpenADUser : GetOpenADOperation
    {
        internal override (string, bool)[] DefaultProperties => OpenADUser.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADUser(attributes);

        internal override string ParseIdentityToFilter(string identity) => $"(distinguishedName={Identity})";
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADGroup",
        DefaultParameterSetName = "Identity"
    )]
    [OutputType(typeof(OpenADGroup))]
    public class GetOpenADGroup : GetOpenADOperation
    {
        internal override (string, bool)[] DefaultProperties => OpenADGroup.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADGroup(attributes);

        internal override string ParseIdentityToFilter(string identity) => $"(distinguishedName={Identity})";
    }
}
