using PSOpenAD.LDAP;
using System;
using System.Management.Automation;
using System.Security.Authentication;
using System.Threading;

namespace PSOpenAD.Commands
{
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
        public Uri Uri { get; set; } = new Uri("ldap://default"); // dummy value used to satisfy the null reference warnings

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
        public SwitchParameter UseSSL { get; set; }

        [Parameter()]
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
            if (ParameterSetName == "ComputerName")
            {
                string scheme = UseSSL ? "ldaps" : "ldap";
                int port = Port != 0 ? Port : (UseSSL ? 636 : 389);
                Uri = new Uri($"{scheme}://{ComputerName}:{port}");
            }

            using (CurrentCancelToken = new CancellationTokenSource())
            {
                try
                {
                    OpenADSession session = OpenADSessionFactory.Create(Uri, Credential, AuthType, StartTLS,
                        SessionOption, CurrentCancelToken.Token, cmdlet: this);
                    GlobalState.AddSession(Uri.ToString(), session);
                    WriteObject(session);
                }
                catch (LDAPException e)
                {
                    WriteError(new ErrorRecord(e, "LDAPError", ErrorCategory.ProtocolError, null));
                }
                catch (AuthenticationException e)
                {
                    WriteError(new ErrorRecord(e, "AuthError", ErrorCategory.AuthenticationError, null));
                }
                catch (ArgumentException e)
                {
                    WriteError(new ErrorRecord(e, "InvalidParameter", ErrorCategory.InvalidArgument, null));
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
}
