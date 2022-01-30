using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Reflection;
using System.Threading;

namespace PSOpenAD.Commands;

public abstract class GetOpenADOperation : PSCmdlet
{
    internal LDAPFilter? _ldapFilter;
    internal bool _includeDeleted = false;

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    internal abstract (string, bool)[] DefaultProperties { get; }

    internal abstract LDAPFilter FilteredClass { get; }

    internal abstract OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes);

    #region Connection Parameters

    [Parameter(
        Mandatory = true,
        ParameterSetName = "SessionIdentity"
    )]
    [Parameter(
        Mandatory = true,
        ParameterSetName = "SessionLDAPFilter"
    )]
    public OpenADSession? Session { get; set; }

    [Parameter(ParameterSetName = "ServerIdentity")]
    [Parameter(ParameterSetName = "ServerLDAPFilter")]
    [ArgumentCompleter(typeof(ServerCompleter))]
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
    public string LDAPFilter { get; set; } = "";

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
    [ArgumentCompleter(typeof(PropertyCompleter))]
    public string[]? Property { get; set; }

    #endregion

    protected override void ProcessRecord()
    {
        if (_ldapFilter == null)
        {
            try
            {
                _ldapFilter = LDAP.LDAPFilter.ParseFilter(LDAPFilter);
            }
            catch (InvalidLDAPFilterException e)
            {
                ErrorRecord rec = new(
                    e,
                    "InvalidLDAPFilterException",
                    ErrorCategory.ParserError,
                    LDAPFilter);

                rec.ErrorDetails = new($"Failed to parse LDAP Filter: {e.Message}");

                // By setting the InvocationInfo we get a nice error description in PowerShell with positional
                // details. Unfortunately this is not publicly settable so we have to use reflection.
                if (!string.IsNullOrWhiteSpace(e.Filter))
                {
                    ScriptPosition start = new("", 1, e.StartPosition + 1, e.Filter);
                    ScriptPosition end = new("", 1, e.EndPosition + 1, e.Filter);
                    InvocationInfo info = InvocationInfo.Create(
                        MyInvocation.MyCommand,
                        new ScriptExtent(start, end));
                    rec.GetType().GetField(
                        "_invocationInfo",
                        BindingFlags.NonPublic | BindingFlags.Instance)?.SetValue(rec, info);
                }

                ThrowTerminatingError(rec);
                return; // Satisfies nullability checks
            }
        }
        LDAPFilter finalFilter = new FilterAnd(new[] { FilteredClass, _ldapFilter });

        StringComparer comparer = StringComparer.OrdinalIgnoreCase;
        HashSet<string> requestedProperties = DefaultProperties.Select(p => p.Item1).ToHashSet(comparer);
        string[] explicitProperties = Property ?? Array.Empty<string>();
        bool showAll = false;
        foreach (string prop in explicitProperties)
        {
            if (prop == "*") { showAll = true; }
            requestedProperties.Add(prop);
        }

        List<LDAPControl>? serverControls = null;
        if (_includeDeleted)
        {
            serverControls = new();
            serverControls.Add(new("1.2.840.113556.1.4.417", false, null)); // LDAP_SERVER_SHOW_DELETED_OID
            serverControls.Add(new("1.2.840.113556.1.4.2065", false, null)); // LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID
        }

        using (CurrentCancelToken = new CancellationTokenSource())
        {
            if (Session == null)
            {
                Session = OpenADSessionFactory.CreateOrUseDefault(Server, Credential, AuthType, StartTLS,
                    SessionOption, CurrentCancelToken.Token, this);
            }

            if (Session == null)
                return; // Failed to create session - error records have already been written.

            string searchBase = SearchBase ?? Session.DefaultNamingContext;
            bool outputResult = false;

            foreach (SearchResultEntry result in Operations.LdapSearchRequest(Session.Connection, searchBase,
                SearchScope, 0, Session.OperationTimeout, finalFilter, requestedProperties.ToArray(), serverControls,
                CurrentCancelToken.Token, this))
            {
                Dictionary<string, (PSObject[], bool)> props = new();
                foreach (PartialAttribute attribute in result.Attributes)
                {
                    props[attribute.Name] = Session.SchemaMetadata.TransformAttributeValue(attribute.Name,
                        attribute.Values, this);
                }

                OpenADObject adObj = CreateADObject(props);

                // This adds a note property for each explicitly requested property, excluding the ones the object
                // naturally exposes.
                PSObject adPSObj = PSObject.AsPSObject(adObj);
                List<string> orderedProps = props.Keys
                    .Where(v =>
                        (showAll || explicitProperties.Contains(v, comparer)) &&
                        !DefaultProperties.Contains((v, true)))
                    .OrderBy(v => v)
                    .ToList();

                foreach (string p in orderedProps)
                {
                    (object value, bool isSingleValue) = props[p];
                    if (isSingleValue)
                    {
                        value = ((IList<PSObject>)value)[0];
                    }

                    adPSObj.Properties.Add(new PSNoteProperty(p, value));
                }

                outputResult = true;
                WriteObject(adObj);
            }

            if (ParameterSetName.EndsWith("Identity") && !outputResult)
            {
                string msg = $"Cannot find an object with identity filter: '{finalFilter}' under: '{searchBase}'";
                ErrorRecord rec = new(new ItemNotFoundException(msg), "IdentityNotFound",
                    ErrorCategory.ObjectNotFound, finalFilter.ToString());
                WriteError(rec);
            }
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
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

    internal override LDAPFilter FilteredClass => new FilterPresent("objectClass");

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new(attributes);
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

    internal override LDAPFilter FilteredClass
        => new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("computer"));

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADComputer(attributes);
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

    internal override LDAPFilter FilteredClass
        => new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("person"));

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADUser(attributes);
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

    internal override LDAPFilter FilteredClass
        => new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("group"));

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADGroup(attributes);
}
