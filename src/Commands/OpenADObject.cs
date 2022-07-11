using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Reflection;
using System.Threading;

namespace PSOpenAD.Commands;

public abstract class GetOpenADOperation<T> : PSCmdlet
    where T : ADObjectIdentity
{
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
    [Credential()]
    public PSCredential? Credential { get; set; }

    #endregion

    #region LDAPFilter Parameters

    [Parameter(
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ServerLDAPFilter"
    )]
    [Parameter(
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "SessionLDAPFilter"
    )]
    public string? LDAPFilter { get; set; }

    [Parameter(ParameterSetName = "ServerLDAPFilter")]
    [Parameter(ParameterSetName = "SessionLDAPFilter")]
    public string? SearchBase { get; set; }

    [Parameter(ParameterSetName = "ServerLDAPFilter")]
    [Parameter(ParameterSetName = "SessionLDAPFilter")]
    public SearchScope SearchScope { get; set; } = SearchScope.Subtree;

    #endregion

    #region Identity Parameters

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
    public T? Identity { get; set; }

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
        LDAPFilter finalFilter;
        if (!string.IsNullOrWhiteSpace(LDAPFilter))
        {
            LDAPFilter subFilter;
            try
            {
                subFilter = LDAP.LDAPFilter.ParseFilter(LDAPFilter);
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

            finalFilter = new FilterAnd(new[] { FilteredClass, subFilter });
        }
        else if (Identity != null)
        {
            finalFilter = new FilterAnd(new[] { FilteredClass, Identity.LDAPFilter });
        }
        else
        {
            finalFilter = FilteredClass;
        }

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

            string searchBase = SearchBase ?? Session.DefaultNamingContext;
            bool outputResult = false;

            foreach (SearchResultEntry result in Operations.LdapSearchRequest(Session.Connection, searchBase,
                SearchScope, 0, Session.OperationTimeout, finalFilter, requestedProperties.ToArray(), serverControls,
                CurrentCancelToken.Token, this, false))
            {
                Dictionary<string, (PSObject[], bool)> props = new();
                foreach (PartialAttribute attribute in result.Attributes)
                {
                    props[attribute.Name] = Session.SchemaMetadata.TransformAttributeValue(attribute.Name,
                        attribute.Values, this);
                }

                OpenADObject adObj = CreateADObject(props);

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
    DefaultParameterSetName = "ServerLDAPFilter"
)]
[OutputType(typeof(OpenADObject))]
public class GetOpenADObject : GetOpenADOperation<ADObjectIdentity>
{
    [Parameter()]
    public SwitchParameter IncludeDeletedObjects { get => _includeDeleted; set => _includeDeleted = value; }

    internal override (string, bool)[] DefaultProperties => OpenADObject.DEFAULT_PROPERTIES;

    internal override LDAPFilter FilteredClass => new FilterPresent("objectClass");

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new(attributes);
}

[Cmdlet(
    VerbsCommon.Get, "OpenADComputer",
    DefaultParameterSetName = "ServerLDAPFilter"
)]
[OutputType(typeof(OpenADComputer))]
public class GetOpenADComputer : GetOpenADOperation<ADPrincipalIdentityWithDollar>
{
    internal override (string, bool)[] DefaultProperties => OpenADComputer.DEFAULT_PROPERTIES;

    internal override LDAPFilter FilteredClass
        => new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("computer"));

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADComputer(attributes);
}

[Cmdlet(
    VerbsCommon.Get, "OpenADUser",
    DefaultParameterSetName = "ServerLDAPFilter"
)]
[OutputType(typeof(OpenADUser))]
public class GetOpenADUser : GetOpenADOperation<ADPrincipalIdentity>
{
    internal override (string, bool)[] DefaultProperties => OpenADUser.DEFAULT_PROPERTIES;

    internal override LDAPFilter FilteredClass
        => new FilterAnd(new LDAPFilter[] {
            new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("person")),
            new FilterEquality("objectClass", LDAP.LDAPFilter.EncodeSimpleFilterValue("user"))
        });

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADUser(attributes);
}

[Cmdlet(
    VerbsCommon.Get, "OpenADGroup",
    DefaultParameterSetName = "ServerLDAPFilter"
)]
[OutputType(typeof(OpenADGroup))]
public class GetOpenADGroup : GetOpenADOperation<ADPrincipalIdentity>
{
    internal override (string, bool)[] DefaultProperties => OpenADGroup.DEFAULT_PROPERTIES;

    internal override LDAPFilter FilteredClass
        => new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("group"));

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADGroup(attributes);
}

[Cmdlet(
    VerbsCommon.Get, "OpenADServiceAccount",
    DefaultParameterSetName = "ServerLDAPFilter"
)]
[OutputType(typeof(OpenADServiceAccount))]
public class GetOpenADServiceAccount : GetOpenADOperation<ADPrincipalIdentityWithDollar>
{
    internal override (string, bool)[] DefaultProperties => OpenADServiceAccount.DEFAULT_PROPERTIES;

    internal override LDAPFilter FilteredClass
        => new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("msDS-GroupManagedServiceAccount"));

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADServiceAccount(attributes);
}
