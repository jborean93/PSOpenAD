using System;
using System.Management.Automation;
using System.Threading;

namespace PSOpenAD.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADSession"
)]
[OutputType(typeof(OpenADSession))]
public class GetOpenADSession : PSCmdlet
{
    protected override void EndProcessing()
    {
        // Ensure the sessions are their own collection to avoid something further down the line mutating the same
        // list during an enumeration, e.g. 'Get-OpenADSession | Remove-OpenADSession'
        WriteObject(GlobalState.Sessions.ToArray(), true);
    }
}

[Cmdlet(
    VerbsCommon.New, "OpenADSession",
    DefaultParameterSetName = "ComputerName"
)]
[OutputType(typeof(OpenADSession))]
public class NewOpenADSession : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "Uri"
    )]
    public Uri? Uri { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ComputerName"
    )]
    [ValidateNotNullOrEmpty]
    [Alias("Server")]
    public string ComputerName { get; set; } = "";

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public int Port { get; set; }

    [Parameter(
        ParameterSetName = "ComputerName"
    )]
    public SwitchParameter UseTLS { get; set; }

    [Parameter()]
    [Credential()]
    public PSCredential? Credential { get; set; }

    [Parameter()]
    public AuthenticationMethod AuthType { get; set; } = AuthenticationMethod.Default;

    [Parameter()]
    public SwitchParameter StartTLS { get; set; }

    [Parameter()]
    public OpenADSessionOptions SessionOption { get; set; } = new OpenADSessionOptions();

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    protected override void ProcessRecord()
    {
        if (Uri == null)
        {
            string scheme = UseTLS ? "ldaps" : "ldap";
            int port = Port != 0 ? Port : (UseTLS ? 636 : 389);
            Uri = new Uri($"{scheme}://{ComputerName}:{port}");
        }

        using (CurrentCancelToken = new CancellationTokenSource())
        {
            OpenADSession? session = OpenADSessionFactory.CreateOrUseDefault(Uri.ToString(), Credential, AuthType,
                StartTLS, SessionOption, CurrentCancelToken.Token, this, skipCache: true);

            if (session != null)
            {
                WriteObject(session);
            }
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
    }
}

[Cmdlet(
    VerbsCommon.Remove, "OpenADSession"
)]
public class RemoveOpenADSession : PSCmdlet
{
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public OpenADSession[] Session { get; set; } = Array.Empty<OpenADSession>();

    protected override void ProcessRecord()
    {
        foreach (OpenADSession s in Session)
        {
            WriteVerbose($"Closing connection to {s.Uri}");
            s.Close();
        }
    }
}
