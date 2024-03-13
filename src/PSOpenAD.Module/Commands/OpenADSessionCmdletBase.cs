using PSOpenAD.LDAP;
using System;
using System.Linq;
using System.Management.Automation;
using System.Threading;

namespace PSOpenAD.Module.Commands;

public abstract class OpenADCancellableCmdlet : PSCmdlet, IDisposable
{
    private bool _disposed = false;

    private CancellationTokenSource _cancelTokenSource = new();

    protected CancellationToken CancelToken
    {
        get => _cancelTokenSource.Token;
    }

    protected override void StopProcessing()
    {
        _cancelTokenSource.Cancel();
    }

    public void Dispose()
    {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _cancelTokenSource.Dispose();
        }
        _disposed = true;
    }
}

public abstract class OpenADSessionCmdletBase : OpenADCancellableCmdlet
{
    internal const string DefaultSessionParameterSet = "Server";

    [Parameter(
        Mandatory = true,
        ParameterSetName = "Session"
    )]
    public virtual OpenADSession? Session { get; set; }

    [Parameter(ParameterSetName = DefaultSessionParameterSet)]
    [ArgumentCompleter(typeof(ServerCompleter))]
    public virtual string Server { get; set; } = "";

    [Parameter(ParameterSetName = DefaultSessionParameterSet)]
    public virtual AuthenticationMethod AuthType { get; set; } = AuthenticationMethod.Default;

    [Parameter(ParameterSetName = DefaultSessionParameterSet)]
    public virtual OpenADSessionOptions SessionOption { get; set; } = new OpenADSessionOptions();

    [Parameter(ParameterSetName = DefaultSessionParameterSet)]
    public virtual SwitchParameter StartTLS { get; set; }

    [Parameter(ParameterSetName = DefaultSessionParameterSet)]
    [Credential()]
    public virtual PSCredential? Credential { get; set; }

    protected override void ProcessRecord()
    {
        OpenADSession? session = Session ?? OpenADSessionFactory.CreateOrUseDefault(
            Server,
            Credential,
            AuthType,
            StartTLS,
            SessionOption,
            CancelToken,
            this
        );

        // If null, it failed to create session - error records have already been written.
        if (session != null)
        {
            ProcessRecordWithSession(session);
        }
    }

    protected abstract void ProcessRecordWithSession(OpenADSession session);

    internal string? GetIdentityDistinguishedName(
        ADObjectIdentity identity,
        OpenADSession session,
        string verb)
    {
        WriteVerbose($"Attempting to get distinguishedName for object with filter '{identity.LDAPFilter}'");

        SearchResultEntry? entryResult = Operations.LdapSearchRequest(
            session.Connection,
            session.DefaultNamingContext,
            SearchScope.Subtree,
            0,
            session.OperationTimeout,
            identity.LDAPFilter,
            new[] { "distinguishedName" },
            null,
            CancelToken,
            this,
            false
        ).FirstOrDefault();

        PartialAttribute? dnResult = entryResult?.Attributes
            .Where(a => string.Equals(a.Name, "distinguishedName", StringComparison.InvariantCultureIgnoreCase))
            .FirstOrDefault();
        if (dnResult == null)
        {
            ErrorRecord error = new(
                new ArgumentException($"Failed to find object to set using the filter '{identity.LDAPFilter}'"),
                $"CannotFind{verb}ObjectWithFilter",
                ErrorCategory.InvalidArgument,
                identity);
            WriteError(error);
            return null;
        }

        (PSObject[] rawDn, bool _) = session.SchemaMetadata.TransformAttributeValue(
            dnResult.Name,
            dnResult.Values,
            this);
        return (string)rawDn[0].BaseObject;
    }
}
