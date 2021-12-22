using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Commands
{
    public abstract class GetOpenADOperation : PSCmdlet
    {
        internal string _ldapFilter = "";
        internal bool _includeDeleted = false;

        internal abstract (string, bool)[] DefaultProperties { get; }

        internal abstract OpenADObject CreateADObject(Dictionary<string, object?> attributes);

        #region Connection Parameters

        [Parameter(
            Mandatory = true,
            ParameterSetName = "SessionIdentity"
        )]
        [Parameter(
            Mandatory = true,
            ParameterSetName = "SessionLDAPFilter"
        )]
        public OpenADSession Session { get; set; } = null!;

        [Parameter(ParameterSetName = "ServerIdentity")]
        [Parameter(ParameterSetName = "ServerLDAPFilter")]
        public string Server { get; set; } = "";

        [Parameter(ParameterSetName = "ServerIdentity")]
        [Parameter(ParameterSetName = "ServerLDAPFilter")]
        public AuthenticationMethod AuthType { get; set; } = AuthenticationMethod.Default;

        [Parameter(ParameterSetName = "ServerIdentity")]
        [Parameter(ParameterSetName = "ServerLDAPFilter")]
        public OpenADSessionOptions SessionOption { get; set; } = new OpenADSessionOptions();

        [Parameter(ParameterSetName = "ServerIdentity")]
        [Parameter(ParameterSetName = "ServerLDAPFilter")]
        public SwitchParameter StartTLS { get; set; }

        [Parameter(ParameterSetName = "ServerIdentity")]
        [Parameter(ParameterSetName = "ServerLDAPFilter")]
        public PSCredential? Credential { get; set; }

        #endregion

        #region LDAPFilter Parameters

        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "ServerLDAPFilter"
        )]
        [Parameter(
            Mandatory = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "SessionLDAPFilter"
        )]
        public string LDAPFilter { get => _ldapFilter; set => _ldapFilter = value; }

        [Parameter(ParameterSetName = "ServerLDAPFilter")]
        [Parameter(ParameterSetName = "SessionLDAPFilter")]
        public string? SearchBase { get; set; }

        [Parameter(ParameterSetName = "ServerLDAPFilter")]
        [Parameter(ParameterSetName = "SessionLDAPFilter")]
        public SearchScope SearchScope { get; set; } = SearchScope.Subtree;

        #endregion

        #region Common Parameters

        [Parameter()]
        [Alias("Properties")]
        [ValidateNotNullOrEmpty]
        public string[]? Property { get; set; }

        #endregion

        protected override void ProcessRecord()
        {
            StringComparer comparer = StringComparer.OrdinalIgnoreCase;
            HashSet<string> requestedProperties = DefaultProperties.Select(p => p.Item1).ToHashSet(comparer);
            string[] explicitProperties = Property ?? Array.Empty<string>();
            bool showAll = false;
            foreach (string prop in explicitProperties)
            {
                if (prop == "*") { showAll = true; }
                requestedProperties.Add(prop);
            }

            List<LDAPControl> serverControls = new List<LDAPControl>();
            if (_includeDeleted)
            {
                serverControls.Add(new LDAPControl(LDAPControl.LDAP_SERVER_SHOW_DELETED_OID, null, false));
                serverControls.Add(new LDAPControl(LDAPControl.LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID, null, false));
            }

            if (ParameterSetName.StartsWith("Server"))
            {
                Uri ldapUri;
                if (string.IsNullOrEmpty(Server))
                {
                    if (string.IsNullOrEmpty(GlobalState.DefaultRealm))
                    {
                        return;
                    }

                    ldapUri = new Uri($"ldap://{GlobalState.DefaultRealm}:389/");
                }
                else if (Server.StartsWith("ldap://", true, CultureInfo.InvariantCulture) ||
                    Server.StartsWith("ldaps://", true, CultureInfo.InvariantCulture))
                {
                    ldapUri = new Uri(Server);
                }
                else
                {
                    ldapUri = new Uri($"ldap://{Server}:389/");
                }

                Session = OpenADSessionFactory.CreateOrUseDefault(ldapUri, Credential, AuthType,
                    StartTLS, SessionOption, this);
            }

            string searchBase = SearchBase ?? Session.DefaultNamingContext;
            LDAPSearchScope ldapScope = (LDAPSearchScope)SearchScope;

            int msgid = OpenLDAP.SearchExt(Session.Handle, searchBase, ldapScope, _ldapFilter,
                requestedProperties.ToArray(), false, serverControls: serverControls.ToArray());
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
                    .Where(v => (showAll || explicitProperties.Contains(v, comparer)) && !DefaultProperties.Contains((v, true)))
                    .OrderBy(v => v)
                    .ToList()
                    .ForEach(v => adPSObj.Properties.Add(new PSNoteProperty(v, props[v])));

                // FIXME: Fail if -Identity is used and either 0 or multiple objects found.
                WriteObject(adObj);
            }
        }
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADObject",
        DefaultParameterSetName = "ServerIdentity"
    )]
    [OutputType(typeof(OpenADObject))]
    public class GetOpenADObject : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "ServerIdentity"
        )]
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "SessionIdentity"
        )]
        public ADObjectIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        [Parameter()]
        public SwitchParameter IncludeDeletedObjects { get => _includeDeleted; set => _includeDeleted = value; }

        internal override (string, bool)[] DefaultProperties => OpenADObject.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADObject(attributes);
    }


    [Cmdlet(
        VerbsCommon.Get, "OpenADComputer",
        DefaultParameterSetName = "ServerIdentity"
    )]
    [OutputType(typeof(OpenADComputer))]
    public class GetOpenADComputer : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "ServerIdentity"
        )]
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "SessionIdentity"
        )]
        public ADPrincipalIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        internal override (string, bool)[] DefaultProperties => OpenADComputer.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADComputer(attributes);
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADUser",
        DefaultParameterSetName = "ServerIdentity"
    )]
    [OutputType(typeof(OpenADUser))]
    public class GetOpenADUser : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "ServerIdentity"
        )]
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "SessionIdentity"
        )]
        public ADPrincipalIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        internal override (string, bool)[] DefaultProperties => OpenADUser.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADUser(attributes);
    }

    [Cmdlet(
        VerbsCommon.Get, "OpenADGroup",
        DefaultParameterSetName = "ServerIdentity"
    )]
    [OutputType(typeof(OpenADGroup))]
    public class GetOpenADGroup : GetOpenADOperation
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "ServerIdentity"
        )]
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "SessionIdentity"
        )]
        public ADPrincipalIdentity Identity { get => null!; set => _ldapFilter = value.LDAPFilter; }

        internal override (string, bool)[] DefaultProperties => OpenADGroup.DEFAULT_PROPERTIES;

        internal override OpenADObject CreateADObject(Dictionary<string, object?> attributes) => new OpenADGroup(attributes);
    }
}
