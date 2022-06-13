using PSOpenAD.LDAP;
using System;
using System.Management.Automation;
using System.Text;
using System.Threading;

namespace PSOpenAD.Commands;

/// <summary>The result from a LDAP Whoami request operation.</summary>
public sealed class WhoamiResult
{
    /// <summary>The username without the u: prefix found in the raw result.</summary>
    public string UserName => RawUserName.StartsWith("u:") ? RawUserName[2..] : RawUserName;

    /// <summary>The LDAP connection URI used for the whoami request.</summary>
    public Uri Uri { get; }

    /// <summary>The domain controller the request was sent to.</summary>
    public string DomainController { get; }

    /// <summary>The authentication method used for the LDAP session that did the whoami request.</summary>
    public AuthenticationMethod Authentication { get; }

    /// <summary>The raw result from the LDAP whoami request.</summary>
    public string RawUserName { get; }

    internal WhoamiResult(string result, Uri uri, string domainController, AuthenticationMethod authentication)
    {
        RawUserName = result;
        Uri = uri;
        DomainController = domainController;
        Authentication = authentication;
    }
}

[Cmdlet(
    VerbsCommon.Get, "OpenADWhoami",
    DefaultParameterSetName = "Server"
)]
[OutputType(typeof(WhoamiResult))]
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
    [Credential()]
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
            WriteObject(new WhoamiResult(i, Session.Uri, Session.DomainController, Session.Authentication));
        }
    }

    protected override void StopProcessing()
    {
        CurrentCancelToken?.Cancel();
    }
}
