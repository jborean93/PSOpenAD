using PSOpenAD.LDAP;
using System;
using System.Globalization;
using System.Management.Automation;
using System.Text;
using System.Threading;

namespace PSOpenAD.Commands
{
    [Cmdlet(
        VerbsCommon.Get, "OpenADWhoami",
        DefaultParameterSetName = "Server"
    )]
    [OutputType(typeof(string))]
    public class GetOpenADWhoami : PSCmdlet
    {
        [Parameter(Mandatory = true, ParameterSetName = "Session")]
        public OpenADSession Session { get; set; } = null!;

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
                if (ParameterSetName == "Server")
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
                        StartTLS, SessionOption, cancelToken: CurrentCancelToken.Token, cmdlet: this);
                }

                int whoamiId = Session.Ldap.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3");
                ExtendedResponse extResp = (ExtendedResponse)Session.Connection.WaitForMessage(whoamiId,
                    cancelToken: CurrentCancelToken.Token);
                if (extResp.Result.ResultCode != LDAPResultCode.Success)
                    throw new LDAPException(extResp.Result);

                if (extResp.Value != null)
                {
                    WriteObject(Encoding.UTF8.GetString(extResp.Value));
                }
                else
                {
                    WriteObject("Unknown");
                }
            }
        }

        protected override void StopProcessing()
        {
            CurrentCancelToken?.Cancel();
        }
    }
}
