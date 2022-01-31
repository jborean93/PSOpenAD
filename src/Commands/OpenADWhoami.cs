using PSOpenAD.LDAP;
using System.Management.Automation;
using System.Text;
using System.Threading;

namespace PSOpenAD.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADWhoami",
    DefaultParameterSetName = "Server"
)]
[OutputType(typeof(string))]
public class GetOpenADWhoami : PSCmdlet
{
    [Parameter(Mandatory = true, ParameterSetName = "Session")]
    public OpenADSession? Session { get; set; }

    [Parameter(ParameterSetName = "Server")]
    public string Server { get; set; } = "";

    [Parameter(ParameterSetName = "Server")]
    public AuthenticationMethod AuthType { get; set; } = AuthenticationMethod.Default;

    [Parameter(ParameterSetName = "Server")]
    public OpenADSessionOptions SessionOption { get; set; } = new OpenADSessionOptions();

    [Parameter(ParameterSetName = "Server")]
    public SwitchParameter StartTLS { get; set; }

    [Parameter(ParameterSetName = "Server")]
    public PSCredential? Credential { get; set; }

    private CancellationTokenSource? CurrentCancelToken { get; set; }

    protected override void ProcessRecord()
    {
        using (CurrentCancelToken = new CancellationTokenSource())
        {
            if (Session == null)
            {
                Session = OpenADSessionFactory.CreateOrUseDefault(Server, Credential, AuthType, StartTLS,
                    SessionOption, CurrentCancelToken.Token, this);
            }

            if (Session == null)
                return; // Failed to create session - error records have already been written.

            int whoamiId = Session.Ldap.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
            ExtendedResponse extResp = (ExtendedResponse)Session.Connection.WaitForMessage(whoamiId,
                cancelToken: CurrentCancelToken.Token);
            if (extResp.Result.ResultCode != LDAPResultCode.Success)
            {
                LDAPException e = new(extResp.Result);
                WriteError(new ErrorRecord(e, "LDAPError", ErrorCategory.ProtocolError, null));
                return;
            }

            string i = extResp.Value == null ? "Unknown" : Encoding.UTF8.GetString(extResp.Value);
            WriteObject(i);
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
    }
}
