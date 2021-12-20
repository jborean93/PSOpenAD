using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Text.RegularExpressions;
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
            AuthenticationProvider? selectedAuth = ClientAuthentication.Providers.Find(
                (AuthenticationProvider p) => p.Method == Authentication);
            if (selectedAuth?.Available != true)
            {
                ArgumentException ex = new ArgumentException(
                    $"Client cannot offer -Authentication {Authentication} as it is not available");
                WriteError(new ErrorRecord(ex, "InvalidAuthenticationSpecified", ErrorCategory.InvalidArgument,
                    null));
                return;
            }

            if (this.ParameterSetName == "ComputerName")
            {
                string scheme = UseSSL ? "ldaps" : "ldap";
                int port = Port != 0 ? Port : (UseSSL ? 636 : 389);
                Uri = new Uri($"{scheme}://{ComputerName}:{port}");
            }

            WriteVerbose($"Initializing LDAP with {Uri}");
            var ldap = OpenLDAP.Initialize(Uri.ToString());
            OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_PROTOCOL_VERSION, 3);

            bool transportIsTLS = false;
            if (StartTLS || Uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
            {
                transportIsTLS = true;

                if (NoEncryption || NoSigning)
                {
                    ArgumentException ex = new ArgumentException(
                        "Cannot disable encryption or signatures for TLS based connection");
                    WriteError(new ErrorRecord(ex, "DisableTLSSecurity", ErrorCategory.InvalidArgument, null));
                    return;
                }

                // OpenLDAP disables channel binding by default but MS most likely requires it when using GSSAPI auth.
                // Change the default to enabled with an opt-in switch to disable it if needed. This requires a
                // patched version of cyrus-sasl for it to work with GSSAPI auth.
                // https://github.com/cyrusimap/cyrus-sasl/commit/975edbb69070eba6b035f08776de771a129cfb57
                if (!NoChannelBinding && !selectedAuth.SupportsCB)
                    WriteWarning("Could not detect if auth supports channel binding, authentication could fail");

                int cbindingValue = NoChannelBinding
                    ? (int)LDAPChannelBinding.LDAP_OPT_X_SASL_CBINDING_NONE
                    : (int)LDAPChannelBinding.LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT;
                WriteVerbose($"Setting SASL_CBINDING to {cbindingValue}");
                OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_CBINDING, cbindingValue);

                if (SkipCertificateCheck)
                {
                    // Once setting the option we need to ensure a new context is used rather than the global one.
                    WriteVerbose("Skipping certificate verification checks for connection");
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_REQUIRE_CERT,
                        (int)LDAPTlsSettings.LDAP_OPT_X_TLS_NEVER);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_NEWCTX, 0);
                }

                if (StartTLS && Uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
                {
                    ArgumentException ex = new ArgumentException("Cannot use StartTLS over an LDAPS connection");
                    WriteError(new ErrorRecord(ex, "StartTLSWithLDAPS", ErrorCategory.InvalidArgument, null));
                    return;
                }
                else if (StartTLS)
                {
                    WriteVerbose("Running StartTLS on the LDAP connection");
                    OpenLDAP.StartTlsS(ldap);
                }
            }

            string username = Credential?.UserName ?? "";
            string password = Credential?.GetNetworkCredential().Password ?? "";
            bool isSigned = false;
            bool isEncrypted = false;

            if (Authentication == AuthenticationMethod.Anonymous)
            {
                WriteVerbose("Connecting to LDAP host with ANONYMOUS auth");
                throw new ArgumentException(nameof(AuthenticationMethod));
            }
            else if (Authentication == AuthenticationMethod.Simple)
            {
                WriteVerbose("Connecting to LDAP host with SIMPLE auth");
                SimpleBind(ldap, username, password);
            }
            else
            {
                WriteVerbose($"Connecting to LDAP host with SASL {Authentication} auth");

                if (transportIsTLS || (NoSigning && NoEncryption))
                {
                    // MS does not allow integrity/confidentiality inside a TLS session. Set this flag to tell SASL not
                    // to configure the connection for this.
                    WriteVerbose("Disabling SASL encryption/signing with SSF min/max to 0");
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MIN, 0);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MAX, 0);
                }
                else if (NoEncryption)
                {
                    // SSF of 1 means integrity (signing), anything above that is encryption.
                    WriteVerbose("Disabling SASL encryption with SSF min/max to 1");
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MIN, 1);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MAX, 1);

                    // Seems like the GSS-SPNEGO SASL mech can only encrypt or do nothing. It cannot do signatures
                    // only like GSSAPI/Kerberos.
                    if (Authentication == AuthenticationMethod.Negotiate)
                        WriteWarning("-NoEncryption on Negotiate does not work without -NoSigning");
                }

                // Using an explicit credential in LDAP/SASL for GSSAPI is difficult. The code gets the credential
                // object using gss_acquire_cred_with_password then passes that into the SASL prompter. This prompter
                // will call ldap_set_option(LDAP_OPT_X_SASL_GSS_CREDS, cred) to tell SASL to use these creds rather
                // than the default ccache. The ldap_set_option cannot be called before the bind starts as it requires
                // an initialised SASL context which is only done once the bind starts. By using the prompter the
                // option can be set as the SASL context will have been created.
                byte[] mech = Authentication == AuthenticationMethod.Negotiate
                    ? GSSAPI.SPNEGO
                    : GSSAPI.KERBEROS;

                GssapiCredential cred;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    WriteVerbose("Getting GSSAPI credential with explicit credentials");
                    using SafeGssapiName name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);
                    cred = GSSAPI.AcquireCredWithPassword(name, password, 0, new List<byte[]> { mech },
                        GssapiCredUsage.GSS_C_INITIATE);
                }
                else if (!string.IsNullOrEmpty(username))
                {
                    WriteVerbose("Getting cached GSSAPI credential for explicit user");
                    using SafeGssapiName name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);
                    cred = GSSAPI.AcquireCred(name, 0, new List<byte[]> { mech }, GssapiCredUsage.GSS_C_INITIATE);
                }
                else
                {
                    WriteVerbose("Getting cached GSSAPI credential");
                    cred = GSSAPI.AcquireCred(null, 0, new List<byte[]> { mech }, GssapiCredUsage.GSS_C_INITIATE);
                }

                using (cred)
                {
                    // Newer versions of cyrus-sasl will do this for us but we can still manually do this for
                    // compatibility with older versions. This tells the GSSAPI context to really turn off integration
                    // and confidentiality on the connection as that's not allowed by Microsoft when over TLS.
                    // https://github.com/cyrusimap/cyrus-sasl/commit/9de4d7e885c96c68a155d2885c980e1d889129c7#diff-e2efffe07cd6fcacb6d023fdc9c2b3b9d07894bec80bd7ac8ada9e385765f75d
                    if (transportIsTLS)
                    {
                        WriteVerbose("Disabling GSSAPI integrity/encryption for TLS connection");
                        GSSAPI.SetCredOption(cred.Creds, GSSAPI.GSS_KRB5_CRED_NO_CI_FLAGS_X);
                    }

                    GSSAPIPrompter prompter = new GSSAPIPrompter(ldap, cred.Creds);
                    SaslInteractiveBind(ldap, selectedAuth.NativeId, prompter);
                }

                int ssf;
                try
                {
                    ssf = OpenLDAP.GetOptionInt(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF);
                }
                catch (LDAPException)
                {
                    // If the SSF was 0 then the context isn't saved in OpenLDAP and this fails. Mask over this
                    // weirdness.
                    ssf = 0;
                }
                WriteVerbose($"SASL SSF set to {ssf}");
                isSigned = ssf > 0;
                isEncrypted = ssf > 1;
            }

            // Attempt to get the default naming context.
            Dictionary<string, string[]> rootInfo = LdapQuery(ldap, "", LDAPSearchScope.LDAP_SCOPE_BASE, null,
                new string[] { "defaultNamingContext", "subschemaSubentry" });
            string defaultNamingContext = rootInfo["defaultNamingContext"][0];
            string subschemaSubentry = rootInfo["subschemaSubentry"][0];

            // Attempt to get the schema info of the host so the code can parse the raw LDAP attribute values into the
            // required PowerShell type.
            // These attributes are from the below but so far the code only uses the uncommented one.
            // https://ldapwiki.com/wiki/LDAP%20Query%20For%20Schema
            string[] schemaAttributes = new string[]
            {
                "attributeTypes",
                //"dITStructureRules",
                //"objectClasses",
                //"nameForms",
                //"dITContentRules",
                //"matchingRules",
                //"ldapSyntaxes",
                //"matchingRuleUse",
            };
            Dictionary<string, string[]> schemaInfo = LdapQuery(ldap, subschemaSubentry,
                LDAPSearchScope.LDAP_SCOPE_BASE, null, schemaAttributes);

            // foreach (string objectClass in schemaInfo["objectClasses"])
            // {
            //     ObjectClassDefinition def = new ObjectClassDefinition(objectClass);
            // }

            OpenADSession session = new OpenADSession(ldap, Uri, Authentication, transportIsTLS || isSigned,
                transportIsTLS || isEncrypted, defaultNamingContext ?? "");

            foreach (string attributeTypes in schemaInfo["attributeTypes"])
            {
                // In testing 2 attributes (respsTo, and repsFrom) had the string value here
                if (attributeTypes.Contains("SYNTAX 'OctetString'"))
                    attributeTypes.Replace("SYNTAX 'OctetString'", "SYNTAX '1.3.6.1.4.1.1466.115.121.1.40");

                // Neither Syntax or Name should be undefined but they are technically optional in the spec. Write a
                // debug entry to help with future debugging if this becomes more of an issue.
                AttributeTypes attrTypes = new AttributeTypes(attributeTypes);
                if (String.IsNullOrEmpty(attrTypes.Syntax))
                {
                    WriteDebug($"Failed to parse SYNTAX: '{attributeTypes}'");
                    continue;
                }
                if (String.IsNullOrEmpty(attrTypes.Name))
                {
                    WriteDebug($"Failed to parse NAME: '{attributeTypes}'");
                    continue;
                }

                session.AttributeTypes[attrTypes.Name] = attrTypes;
            }

            WriteObject(session);
        }

        protected override void StopProcessing()
        {
            CurrentCancelToken?.Cancel();
        }

        private Dictionary<string, string[]> LdapQuery(SafeLdapHandle ldap, string searchBase, LDAPSearchScope scope,
            string? filter, string[]? attributes)
        {
            int msgid = OpenLDAP.SearchExt(ldap, searchBase, scope, filter, attributes, false);
            Dictionary<string, string[]> result = new Dictionary<string, string[]>();
            using (var res = OpenLDAP.Result(ldap, msgid, LDAPMessageCount.LDAP_MSG_ALL))
            {
                foreach (IntPtr entry in OpenLDAP.GetEntries(ldap, res))
                {
                    foreach (string attribute in OpenLDAP.GetAttributes(ldap, entry))
                    {
                        result[attribute] = OpenLDAP.GetValues(ldap, entry, attribute).Select(
                            v => Encoding.UTF8.GetString(v)).ToArray();
                    }
                }
            }

            return result;
        }

        private void SaslInteractiveBind(SafeLdapHandle ldap, string mech, SaslInteract prompt,
            int timeoutMS = 5000)
        {
            using (CurrentCancelToken = new CancellationTokenSource())
            {
                IntPtr rmech = IntPtr.Zero;
                SafeLdapMessage result = new SafeLdapMessage();

                while (true)
                {
                    (bool more, int msgid) = OpenLDAP.SaslInteractiveBind(ldap, "", mech,
                        SASLInteractionFlags.LDAP_SASL_QUIET, prompt, result, ref rmech);
                    if (!more)
                        break;

                    while (true)
                    {
                        try
                        {
                            result = OpenLDAP.Result(ldap, msgid, LDAPMessageCount.LDAP_MSG_ALL, timeoutMS);
                        }
                        catch (TimeoutException)
                        {
                            timeoutMS -= 200;
                            if (timeoutMS <= 0 || CurrentCancelToken.IsCancellationRequested)
                                throw;

                            continue;
                        }

                        (int rc, string _, string errMsg) = OpenLDAP.ParseResult(ldap, result);
                        if (rc != 0 && rc != (int)LDAPResultCode.LDAP_SASL_BIND_IN_PROGRESS)
                            throw new LDAPException(ldap, rc, "ldap_sasl_interactive_bind", errorMessage: errMsg);

                        break;
                    }
                }
            }
        }

        private void SimpleBind(SafeLdapHandle ldap, string who, string password, int timeoutMS = 5000)
        {
            using (CurrentCancelToken = new CancellationTokenSource())
            {
                int msgid = OpenLDAP.SaslBind(ldap, who, null, Encoding.UTF8.GetBytes(password));

                while (true)
                {
                    SafeLdapMessage result;
                    try
                    {
                        result = OpenLDAP.Result(ldap, msgid, LDAPMessageCount.LDAP_MSG_ALL, timeoutMS);
                    }
                    catch (TimeoutException)
                    {
                        timeoutMS -= 200;
                        if (timeoutMS <= 0 || CurrentCancelToken.IsCancellationRequested)
                            throw;

                        continue;
                    }

                    using (result)
                    {
                        (int rc, string _, string errMsg) = OpenLDAP.ParseResult(ldap, result);
                        if (rc != 0)
                            throw new LDAPException(ldap, rc, "ldap_sasl_bind", errorMessage: errMsg);
                    }
                    break;
                }
            }
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
                s.Handle.Dispose();
                s.IsClosed = true;
            }
        }
    }

    internal class GSSAPIPrompter : SaslInteract
    {
        public SafeLdapHandle Ldap { get; }
        public SafeGssapiCred Cred { get; }

        public GSSAPIPrompter(SafeLdapHandle ldap, SafeGssapiCred cred)
        {
            Ldap = ldap;
            Cred = cred;
        }

        // While the GSSAPI SASL plugin prompts for the user it is not used so just return an empty string.
        public override string GetUser() => "";

        public override void PromptDone()
        {
            // Set the explicit GSSAPI credential for SASL to use.
            OpenLDAP.SetOption(Ldap, LDAPOption.LDAP_OPT_X_SASL_GSS_CREDS, Cred.DangerousGetHandle());
        }
    }
}
