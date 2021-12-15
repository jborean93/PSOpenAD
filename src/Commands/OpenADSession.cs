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
        public SwitchParameter StartTLS { get; set; }

        [Parameter()]
        public PSCredential? Credential { get; set; }

        [Parameter()]
        public AuthenticationMethod Authentication { get; set; } = AuthenticationMethod.Simple;

        [Parameter()]
        public SwitchParameter NoEncryption { get; set; }

        [Parameter()]
        public SwitchParameter NoSigning { get; set; }

        [Parameter()]
        public SwitchParameter NoChannelBinding { get; set; }

        [Parameter()]
        public SwitchParameter SkipCertificateCheck { get; set; }

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

            bool transportIsTLS = false;
            if (StartTLS || Uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
            {
                transportIsTLS = true;

                // OpenLDAP disables channel binding by default but MS most likely requires it when using GSSAPI auth.
                // Change the default to enabled with an opt-in switch to disable it if needed. This requires a
                // patched version of cyrus-sasl for it to work with GSSAPI auth.
                // https://github.com/cyrusimap/cyrus-sasl/commit/975edbb69070eba6b035f08776de771a129cfb57
                int cbindingValue = NoChannelBinding
                    ? (int)LDAPChannelBinding.LDAP_OPT_X_SASL_CBINDING_NONE
                    : (int)LDAPChannelBinding.LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT;
                OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_CBINDING, cbindingValue);

                if (SkipCertificateCheck)
                {
                    // Once setting the option we need to ensure a new context is used rather than the global one.
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_REQUIRE_CERT,
                        (int)LDAPTlsSettings.LDAP_OPT_X_TLS_NEVER);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_NEWCTX, 0);
                }

                if (StartTLS)
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
                if (transportIsTLS || (NoSigning && NoEncryption))
                {
                    // MS does not allow integrity/confidentiality inside a TLS session. Set this flag to tell SASL not
                    // to configure the connection for this. Note this requires a patched version of cyrus-sasl until
                    // they produce a new release.
                    // https://github.com/cyrusimap/cyrus-sasl/commit/9de4d7e885c96c68a155d2885c980e1d889129c7#diff-e2efffe07cd6fcacb6d023fdc9c2b3b9d07894bec80bd7ac8ada9e385765f75d
                    // TODO: Determine how widespread this problem is and potentially set the GSSAPI flags manually.
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MIN, 0);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MAX, 0);
                }
                else if (NoEncryption)
                {
                    // SSF of 1 means integrity (signing), anything above that is encryption.
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MIN, 1);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MAX, 1);
                }

                // Using an explicit credential in LDAP/SASL for GSSAPI is difficult. The code gets the credential
                // object using gss_acquire_cred_with_password then passes that into the SASL prompter. This prompter
                // will call ldap_set_option(LDAP_OPT_X_SASL_GSS_CREDS, cred) to tell SASL to use these creds rather
                // than the default ccache. The ldap_set_option cannot be called before the bind starts as it requires
                // an initialised SASL context which is only done once the bind starts. By using the prompter the
                // option can be set as the SASL context will have been created.
                byte[] mechBytes = Authentication == AuthenticationMethod.Negotiate
                    ? Gssapi.SPNEGO
                    : Gssapi.KERBEROS;
                using GssapiOid mech = new GssapiOid(mechBytes);

                GssapiCredential cred;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    using GssapiOid ntUser = new GssapiOid(Gssapi.GSS_C_NT_USER_NAME);
                    using SafeGssapiName name = Gssapi.ImportName(username, ntUser);

                    cred = Gssapi.AcquireCredWithPassword(name, password, 0, new List<GssapiOid> { mech },
                        GssapiCredUsage.GSS_C_INITIATE);
                }
                else
                {
                    cred = Gssapi.AcquireCred(null, 0, new List<GssapiOid> { mech }, GssapiCredUsage.GSS_C_INITIATE);
                }

                using (cred)
                using (CurrentCancelToken = new CancellationTokenSource())
                {
                    if (transportIsTLS)
                    {
                        using GssapiOid noCIFlags = new GssapiOid(Gssapi.GSS_KRB5_CRED_NO_CI_FLAGS_X);
                        Gssapi.SetCredOption(cred.Creds, noCIFlags);
                    }

                    GSSAPIPrompter prompter = new GSSAPIPrompter(ldap, cred.Creds);
                    Task bindTask = OpenLDAP.SaslInteractiveBindAsync(ldap, "", Authentication, prompter,
                        cancelToken: CurrentCancelToken.Token);
                    bindTask.GetAwaiter().GetResult();
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
