using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;
using System.Threading;

namespace PSOpenAD
{
    public sealed class OpenADSessionOptions
    {
        public bool NoEncryption { get; set; }
        public bool NoSigning { get; set; }
        public bool NoChannelBinding { get; set; }
        public bool SkipCertificateCheck { get; set; }
    }

    public sealed class OpenADSession
    {
        public Uri Uri { get; }

        public AuthenticationMethod Authentication { get; }

        public bool IsSigned { get; }

        public bool IsEncrypted { get; }

        public string DefaultNamingContext { get; internal set; }

        public bool IsClosed { get; internal set; } = false;

        internal SafeLdapHandle Handle { get; }

        internal AttributeTransformer AttributeTransformer { get; }

        internal OpenADSession(SafeLdapHandle ldap, Uri uri, AuthenticationMethod auth, bool isSigned, bool isEncrypted,
            string defaultNamingContext, AttributeTransformer transformer)
        {
            Handle = ldap;
            Uri = uri;
            Authentication = auth;
            IsSigned = isSigned;
            IsEncrypted = isEncrypted;
            DefaultNamingContext = defaultNamingContext;
            AttributeTransformer = transformer;
        }

        internal void Close()
        {
            Handle.Dispose();
            IsClosed = true;
        }
    }

    internal sealed class OpenADSessionFactory
    {
        internal static OpenADSession CreateOrUseDefault(Uri uri, PSCredential? credential,
            AuthenticationMethod auth, bool startTLS, OpenADSessionOptions sessionOptions, PSCmdlet? cmdlet = null,
            CancellationToken? cancelToken = null)
        {
            if (GlobalState.ImplicitSessions.TryGetValue(uri.ToString(), out var session) && !session.IsClosed)
            {
                return session;
            }
            else
            {
                session = Create(uri, credential, auth, startTLS, sessionOptions, cmdlet, cancelToken);
                GlobalState.AddSession(uri.ToString(), session);

                return session;
            }
        }

        internal static OpenADSession Create(Uri uri, PSCredential? credential, AuthenticationMethod auth,
            bool startTLS, OpenADSessionOptions sessionOptions, PSCmdlet? cmdlet = null,
            CancellationToken? cancelToken = null)
        {
            cmdlet?.WriteVerbose($"Initializing LDAP with {uri}");

            var ldap = OpenLDAP.Initialize(uri.ToString());
            OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_PROTOCOL_VERSION, 3);

            bool transportIsTLS = false;
            if (startTLS || uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
            {
                transportIsTLS = true;

                if (sessionOptions.NoEncryption || sessionOptions.NoSigning)
                    throw new ArgumentException("Cannot disable encryption or signatures for TLS based connection");

                // OpenLDAP disables channel binding by default but MS most likely requires it when using GSSAPI auth.
                // Change the default to enabled with an opt-in switch to disable it if needed. This requires a
                // patched version of cyrus-sasl for it to work with GSSAPI auth.
                // https://github.com/cyrusimap/cyrus-sasl/commit/975edbb69070eba6b035f08776de771a129cfb57
                //if (!NoChannelBinding && !selectedAuth.SupportsCB)
                //    WriteWarning("Could not detect if auth supports channel binding, authentication could fail");

                int cbindingValue = sessionOptions.NoChannelBinding
                    ? (int)LDAPChannelBinding.LDAP_OPT_X_SASL_CBINDING_NONE
                    : (int)LDAPChannelBinding.LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT;
                cmdlet?.WriteVerbose($"Setting SASL_CBINDING to {cbindingValue}");
                OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_CBINDING, cbindingValue);

                if (sessionOptions.SkipCertificateCheck)
                {
                    // Once setting the option we need to ensure a new context is used rather than the global one.
                    cmdlet?.WriteVerbose("Skipping certificate verification checks for connection");
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_REQUIRE_CERT,
                        (int)LDAPTlsSettings.LDAP_OPT_X_TLS_NEVER);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_TLS_NEWCTX, 0);
                }

                if (startTLS && uri.Scheme.Equals("ldaps", StringComparison.InvariantCultureIgnoreCase))
                {
                    throw new ArgumentException("Cannot use StartTLS over an LDAPS connection");
                }
                else if (startTLS)
                {
                    cmdlet?.WriteVerbose("Running StartTLS on the LDAP connection");
                    OpenLDAP.StartTlsS(ldap);
                }
            }

            if (auth == AuthenticationMethod.Default)
            {
                // Always favour Negotiate auth if it is available, otherwise use Simple if both a credential and the
                // exchange would be encrypted. If all else fails use an anonymous bind.
                AuthenticationProvider nego = GlobalState.Providers[AuthenticationMethod.Negotiate];
                if (nego.Available)
                {
                    auth = AuthenticationMethod.Negotiate;
                }
                else if (credential != null && transportIsTLS)
                {
                    auth = AuthenticationMethod.Simple;
                }
                else
                {
                    auth = AuthenticationMethod.Anonymous;
                }

                cmdlet?.WriteVerbose($"Setting default auth to {auth}");
            }

            AuthenticationProvider selectedAuth = GlobalState.Providers[auth];
            if (!selectedAuth.Available)
            {
                throw new ArgumentException($"Client cannot offer -Authentication {auth} as it is not available");
            }

            string username = credential?.UserName ?? "";
            string password = credential?.GetNetworkCredential().Password ?? "";
            bool isSigned = false;
            bool isEncrypted = false;

            if (auth == AuthenticationMethod.Anonymous)
            {
                cmdlet?.WriteVerbose("Connecting to LDAP host with ANONYMOUS auth");
                throw new ArgumentException(nameof(AuthenticationMethod));
            }
            else if (auth == AuthenticationMethod.Simple)
            {
                cmdlet?.WriteVerbose("Connecting to LDAP host with SIMPLE auth");
                SimpleBind(ldap, username, password, cancelToken: cancelToken);
            }
            else
            {
                cmdlet?.WriteVerbose($"Connecting to LDAP host with SASL {auth} auth");

                if (transportIsTLS || (sessionOptions.NoSigning && sessionOptions.NoEncryption))
                {
                    // MS does not allow integrity/confidentiality inside a TLS session. Set this flag to tell SASL not
                    // to configure the connection for this.
                    cmdlet?.WriteVerbose("Disabling SASL encryption/signing with SSF min/max to 0");
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MIN, 0);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MAX, 0);
                }
                else if (sessionOptions.NoEncryption)
                {
                    // SSF of 1 means integrity (signing), anything above that is encryption.
                    cmdlet?.WriteVerbose("Disabling SASL encryption with SSF min/max to 1");
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MIN, 1);
                    OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_X_SASL_SSF_MAX, 1);

                    // Seems like the GSS-SPNEGO SASL mech can only encrypt or do nothing. It cannot do signatures
                    // only like GSSAPI/Kerberos.
                    if (auth == AuthenticationMethod.Negotiate)
                        cmdlet?.WriteWarning("-NoEncryption on Negotiate does not work without -NoSigning");
                }

                // Using an explicit credential in LDAP/SASL for GSSAPI is difficult. The code gets the credential
                // object using gss_acquire_cred_with_password then passes that into the SASL prompter. This prompter
                // will call ldap_set_option(LDAP_OPT_X_SASL_GSS_CREDS, cred) to tell SASL to use these creds rather
                // than the default ccache. The ldap_set_option cannot be called before the bind starts as it requires
                // an initialised SASL context which is only done once the bind starts. By using the prompter the
                // option can be set as the SASL context will have been created.
                byte[] mech = auth == AuthenticationMethod.Negotiate ? GSSAPI.SPNEGO : GSSAPI.KERBEROS;

                GssapiCredential cred;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    cmdlet?.WriteVerbose("Getting GSSAPI credential with explicit credentials");
                    using SafeGssapiName name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);
                    cred = GSSAPI.AcquireCredWithPassword(name, password, 0, new List<byte[]> { mech },
                        GssapiCredUsage.GSS_C_INITIATE);
                }
                else if (!string.IsNullOrEmpty(username))
                {
                    cmdlet?.WriteVerbose("Getting cached GSSAPI credential for explicit user");
                    using SafeGssapiName name = GSSAPI.ImportName(username, GSSAPI.GSS_C_NT_USER_NAME);
                    cred = GSSAPI.AcquireCred(name, 0, new List<byte[]> { mech }, GssapiCredUsage.GSS_C_INITIATE);
                }
                else
                {
                    cmdlet?.WriteVerbose("Getting cached GSSAPI credential");
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
                        cmdlet?.WriteVerbose("Disabling GSSAPI integrity/encryption for TLS connection");
                        GSSAPI.SetCredOption(cred.Creds, GSSAPI.GSS_KRB5_CRED_NO_CI_FLAGS_X);
                    }

                    GSSAPIPrompter prompter = new GSSAPIPrompter(ldap, cred.Creds);
                    SaslInteractiveBind(ldap, selectedAuth.NativeId, prompter, cancelToken: cancelToken);
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
                cmdlet?.WriteVerbose($"SASL SSF set to {ssf}");
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

            Dictionary<string, AttributeTypes> attrInfo = new Dictionary<string, AttributeTypes>();
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
                    cmdlet?.WriteDebug($"Failed to parse SYNTAX: '{attributeTypes}'");
                    continue;
                }
                if (String.IsNullOrEmpty(attrTypes.Name))
                {
                    cmdlet?.WriteDebug($"Failed to parse NAME: '{attributeTypes}'");
                    continue;
                }

                attrInfo[attrTypes.Name] = attrTypes;
            }

            return new OpenADSession(ldap, uri, auth, transportIsTLS || isSigned, transportIsTLS || isEncrypted,
                defaultNamingContext ?? "", new AttributeTransformer(attrInfo));
        }


        private static Dictionary<string, string[]> LdapQuery(SafeLdapHandle ldap, string searchBase,
            LDAPSearchScope scope, string? filter, string[]? attributes)
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

        private static void SaslInteractiveBind(SafeLdapHandle ldap, string mech, SaslInteract prompt,
            int timeoutMS = 5000, CancellationToken? cancelToken = null)
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
                        if (timeoutMS <= 0 || cancelToken?.IsCancellationRequested == true)
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

        private static void SimpleBind(SafeLdapHandle ldap, string who, string password, int timeoutMS = 5000,
            CancellationToken? cancelToken = null)
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
                    if (timeoutMS <= 0 || cancelToken?.IsCancellationRequested == true)
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

    internal static class GlobalState
    {
        // Populated by OnImport
        public static Dictionary<AuthenticationMethod, AuthenticationProvider> Providers =
            new Dictionary<AuthenticationMethod, AuthenticationProvider>();

        public static string? DefaultRealm = null;

        public static Dictionary<string, OpenADSession> ImplicitSessions = new Dictionary<string, OpenADSession>(StringComparer.OrdinalIgnoreCase);

        public static void AddSession(string id, OpenADSession session)
        {
            if (ImplicitSessions.ContainsKey(id))
                ImplicitSessions[id].Close();

            ImplicitSessions[id] = session;
        }
    }
}
