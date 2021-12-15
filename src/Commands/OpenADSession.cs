using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;

namespace PSOpenAD.Commands
{
    [Cmdlet(
        VerbsCommon.New, "OpenADSession",
        DefaultParameterSetName = "ComputerName"
    )]
    public class NewOpenADSession : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipelineByPropertyName = true,
            ParameterSetName = "Uri"
        )]
        public Uri Uri { get; set; } = new Uri("ldap://default");

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
        public SwitchParameter UseSSL { get; set; }

        [Parameter(
            ParameterSetName = "ComputerName"
        )]
        public int Port { get; set; }

        [Parameter()]
        public PSCredential? Credential { get; set; }

        [Parameter()]
        public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Simple;

        [Parameter()]
        public SwitchParameter DisableEncryption { get; set; }

        [Parameter()]
        public SwitchParameter DisableSigning { get; set; }

        [Parameter()]
        public SwitchParameter DisableChannelBinding { get; set; }

        [Parameter()]
        public SwitchParameter StartTLS { get; set; }

        [Parameter()]
        public SwitchParameter DisableCertVerification { get; set; }

        private CancellationTokenSource? CurrentCancelToken { get; set; }

        protected override void ProcessRecord()
        {
            if (this.ParameterSetName == "ComputerName")
            {
                string scheme = UseSSL ? "ldaps" : "ldap";
                int port = Port != 0 ? Port : (UseSSL ? 636 : 389);
                Uri = new Uri($"{scheme}://{ComputerName}:{port}");
            }
            var ldap = OpenLDAP.Initialize(Uri.ToString());
            OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_PROTOCOL_VERSION, 3);

            if (StartTLS)
            {
                if (DisableCertVerification)
                {
                    // Once setting the option we need to ensure a new context is used rather than the global one.
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_REQUIRE_CERT,
                        (int)LDAPTlsSettings.LDAP_OPT_X_TLS_NEVER);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_NEWCTX, 0);
                }
                OpenLDAP.StartTlsS(ldap);
            }

            string username = Credential?.UserName ?? "";
            string password = Credential?.GetNetworkCredential().Password ?? "";

            if (Authentication == AuthenticationMethod.Simple)
            {
                using (CurrentCancelToken = new CancellationTokenSource())
                {
                    Task bindTask = OpenLDAP.SimpleBindAsync(ldap, username, password, cancelToken: CurrentCancelToken.Token);
                    bindTask.GetAwaiter().GetResult();
                }
            }
            else
            {
                if (StartTLS) // FIXME Also if ldaps
                {
                    // MS does not allow integrity/confidentiality inside a TLS session. Set this flag to tell SASL not
                    // to configure the connection for this.
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MIN, 0);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MAX, 0);
                }

                // Using an explicit credential in LDAP/SASL for GSSAPI is difficult. The code gets the credential
                // object using gss_acquire_cred_with_password then passes that into the SASL prompter. This prompter
                // will call ldap_set_option(LDAP_OPT_X_SASL_GSS_CREDS, cred) to tell SASL to use these creds rather
                // than the default ccache. The ldap_set_option cannot be called before the bind starts as it requires
                // an initialised SASL context which is only done once the bind starts. By using the prompter the
                // option can be set as the SASL context will have been created.
                GssapiCredential? cred = null;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    using GssapiOid kerb = new GssapiOid(Gssapi.KERBEROS);
                    using GssapiOid ntUser = new GssapiOid(Gssapi.GSS_C_NT_USER_NAME);
                    using SafeGssapiName name = Gssapi.ImportName(username, ntUser);
                    cred = Gssapi.AcquireCredWithPassword(name, password, 0, new List<GssapiOid> { kerb },
                        GssapiCredUsage.GSS_C_INITIATE);
                }

                try
                {
                    GSSAPIPrompter prompter = new GSSAPIPrompter(ldap, cred?.Creds);
                    Task bindTask = OpenLDAP.SaslInteractiveBindAsync(ldap, "", Authentication, prompter);
                    bindTask.GetAwaiter().GetResult();
                }
                finally
                {
                    cred?.Dispose();
                }
            }

            WriteObject(ldap);
        }

        protected override void StopProcessing()
        {
            CurrentCancelToken?.Cancel();
        }
    }

    public enum AuthenticationMethod
    {
        Anonymous,
        Simple,
        Negotiate,
        Kerberos,
    }

    internal class GSSAPIPrompter : SaslInteract
    {
        public SafeLdapHandle Ldap { get; }
        public SafeGssapiCred? Cred { get; }

        public GSSAPIPrompter(SafeLdapHandle ldap, SafeGssapiCred? cred)
        {
            Ldap = ldap;
            Cred = cred;
        }

        // While the GSSAPI SASL plugin prompts for the user it is not used so just return an empty string.
        public override string GetUser() => "";

        public override void PromptDone()
        {
            // Set the explicit GSSAPI credential if one is present.
            if (Cred?.IsClosed == false && Cred?.IsInvalid == false)
                OpenLDAP.SetOption(Ldap, LDAPOption.LDAP_OPT_X_SASL_GSS_CREDS, Cred.DangerousGetHandle());
        }
    }
}
