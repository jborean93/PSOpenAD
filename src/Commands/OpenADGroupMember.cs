using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Reflection;
using System.Threading;

namespace PSOpenAD.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADGroupMember",
    DefaultParameterSetName = "ServerLDAPFilter"
)]
[OutputType(typeof(OpenADPrincipal))]
public class GetOpenADGroupMember : PSCmdlet
{
    internal bool _includeDeleted = false;

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    internal (string, bool)[] DefaultProperties => OpenADPrincipal.DEFAULT_PROPERTIES;

    #region Connection Parameters

    [Parameter(
        Mandatory = true,
        ParameterSetName = "SessionIdentity"
    )]
    public OpenADSession? Session { get; set; }

    [Parameter(ParameterSetName = "ServerIdentity")]
    [ArgumentCompleter(typeof(ServerCompleter))]
    public string Server { get; set; } = "";

    [Parameter(ParameterSetName = "ServerIdentity")]
    public AuthenticationMethod AuthType { get; set; } = AuthenticationMethod.Default;

    [Parameter(ParameterSetName = "ServerIdentity")]
    public OpenADSessionOptions SessionOption { get; set; } = new OpenADSessionOptions();

    [Parameter(ParameterSetName = "ServerIdentity")]
    public SwitchParameter StartTLS { get; set; }

    [Parameter(ParameterSetName = "ServerIdentity")]
    [Credential()]
    public PSCredential? Credential { get; set; }

    #endregion

    #region Identity Parameters

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    [ValidateNotNullOrEmpty]
    public ADPrincipalIdentity? Identity { get; set; }

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
        if (Identity == null) {
            return;
        }

        LDAPFilter finalFilter;
        finalFilter = new FilterAnd(new[] {
            new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("group")),
            Identity.LDAPFilter
        });

        List<LDAPControl>? serverControls = null;
        if (_includeDeleted)
        {
            serverControls = new();
            serverControls.Add(new ShowDeleted(false));
            serverControls.Add(new ShowDeactivatedLink(false));
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

            StringComparer comparer = StringComparer.OrdinalIgnoreCase;
            string className = PropertyCompleter.GetClassNameForCommand(MyInvocation.MyCommand.Name);
            HashSet<string> requestedProperties = DefaultProperties.Select(p => p.Item1).ToHashSet(comparer);
            string[] explicitProperties = Property ?? Array.Empty<string>();
            bool showAll = false;

            // We can only validate modules if there was metadata. Metadata may not be present on all systems and
            // when unauthenticated authentication was used.
            HashSet<string> validProperties;
            ObjectClass? objectClass = Session.SchemaMetadata.GetClassInformation(className);
            if (objectClass is null)
            {
                validProperties = explicitProperties.ToHashSet(comparer);
            }
            else
            {
                validProperties = objectClass.ValidAttributes;
            }

            HashSet<string> invalidProperties = new();

            foreach (string prop in explicitProperties)
            {
                if (prop == "*")
                {
                    showAll = true;
                    requestedProperties.Add(prop);
                    continue;
                }

                if (validProperties.Contains(prop))
                {
                    requestedProperties.Add(prop);
                }
                else
                {
                    invalidProperties.Add(prop);
                }
            }

            if (invalidProperties.Count > 0)
            {
                string sortedProps = string.Join("', '", invalidProperties.OrderBy(p => p).ToArray());
                ErrorRecord rec = new(
                    new ArgumentException($"One or more properties for {className} are not valid: '{sortedProps}'"),
                    "InvalidPropertySet",
                    ErrorCategory.InvalidArgument,
                    null);

                ThrowTerminatingError(rec);
                return;
            }

            string searchBase = Session.DefaultNamingContext;
            bool outputResult = false;

            SearchResultEntry group = Operations.LdapSearchRequest(Session.Connection, searchBase,
                SearchScope.Subtree, 1, Session.OperationTimeout, finalFilter, requestedProperties.ToArray(), serverControls,
                CurrentCancelToken.Token, this, false).FirstOrDefault(); //SingleOrDefault()?
            if (group != null)
            {
                outputResult = true;

                // use memberOf rather than member to make recursive search easier & avoid paging
                FilterEquality memberOfFilter = new FilterEquality("memberOf", LDAP.LDAPFilter.EncodeSimpleFilterValue(group.ObjectName));
                // TODO: Allow recursion with LDAP_MATCHING_RULE_IN_CHAIN/LDAP_MATCHING_RULE_TRANSITIVE_EVAL
                // Manually recursing into groups would also work, not sure where perf sweet spot is.

                foreach (SearchResultEntry result in Operations.LdapSearchRequest(Session.Connection, searchBase,
                    SearchScope.Subtree, 0, Session.OperationTimeout, memberOfFilter, requestedProperties.ToArray(), serverControls,
                    CurrentCancelToken.Token, this, false))
                {
                    Dictionary<string, (PSObject[], bool)> props = new();
                    foreach (PartialAttribute attribute in result.Attributes)
                    {
                        props[attribute.Name] = Session.SchemaMetadata.TransformAttributeValue(attribute.Name,
                            attribute.Values, this);
                    }

                    OpenADPrincipal adObj = new(props);

                    // This adds a note property for each explicitly requested property, excluding the ones the object
                    // naturally exposes. Also adds the DomainController property to denote what DC the response came from.
                    PSObject adPSObj = PSObject.AsPSObject(adObj);
                    adPSObj.Properties.Add(new PSNoteProperty("DomainController", Session.DomainController));

                    List<string> orderedProps = props.Keys
                        .Union(requestedProperties, comparer)
                        .Where(v =>
                            v != "*" &&
                            (showAll || explicitProperties.Contains(v, comparer)) &&
                            !DefaultProperties.Contains((v, true)))
                        .OrderBy(v => v)
                        .ToList();

                    foreach (string p in orderedProps)
                    {
                        object? value = null;
                        if (props.ContainsKey(p))
                        {
                            (value, bool isSingleValue) = props[p];
                            if (isSingleValue)
                            {
                                value = ((IList<PSObject>)value)[0];
                            }
                        }

                        // To make the properties more PowerShell like make sure the first char is in upper case.
                        // PowerShell is case insensitive so users can still select it based on the lower case LDAP name.
                        string propertyName = p[0..1].ToUpperInvariant() + p[1..];
                        adPSObj.Properties.Add(new PSNoteProperty(propertyName, value));
                    }

                    WriteObject(adObj);
                }
            }

            if (!outputResult)
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
