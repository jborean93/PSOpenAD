using System;
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
}
