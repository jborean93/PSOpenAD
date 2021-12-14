using System.Management.Automation;
using System.Threading;
using System.Threading.Tasks;

namespace PSOpenAD.Commands
{
    [Cmdlet(
        VerbsCommon.New, "OpenADSession"
    )]
    public class NewOpenADSession : PSCmdlet
    {
        [Parameter(
            Mandatory = true,
            Position = 0,
            ValueFromPipeline = true,
            ValueFromPipelineByPropertyName = true
        )]
        [ValidateNotNullOrEmpty]
        [Alias("Server")]
        public string ComputerName { get; set; } = "";

        [Parameter()]
        public PSCredential? Credential { get; set; }

        [Parameter()]
        public AuthenticationMethod AuthenticationMethod { get; set; } = AuthenticationMethod.Simple;

        private CancellationTokenSource? CurrentCancelToken { get; set; }

        protected override void ProcessRecord()
        {
            var ldap = OpenLDAP.Initialize($"ldap://{ComputerName}:389");
            OpenLDAP.SetOption(ldap, LDAPOption.LDAP_OPT_PROTOCOL_VERSION, 3);

            string username = Credential?.UserName ?? "";
            string password = Credential?.GetNetworkCredential().Password ?? "";

            if (AuthenticationMethod == AuthenticationMethod.Simple)
            {
                using (CurrentCancelToken = new CancellationTokenSource())
                {
                    Task bindTask = OpenLDAP.SimpleBindAsync(ldap, username, password, cancelToken: CurrentCancelToken.Token);
                    bindTask.GetAwaiter().GetResult();
                }
            }
            else
            {
                // OpenLDAP does not provide a way to provide explicit credentials for Kerberos/GSSAPI authentication.
                // It also does not provide a method to specify an explicit username in a collection of ccaches (it
                // will always use the default). To overcome this issue the krb5 API is used directly to build an
                // in-memory ccache that contains our Kerberos TGT. This in-memory ccache is then set as the default
                // ccache that OpenLDAP will use in the background thread it runs in. The krb5 API is essentially
                // replicating what kinit does but in process and with an in-memory ccache rather than a file.
                string? ccacheName = null;
                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    using SafeKrb5Context ctx = Kerberos.InitContext();
                    using SafeKrb5Principal princ = Kerberos.ParseNameFlags(ctx, username, PrincipalParseFlags.NONE);
                    using SafeKrb5GetInitCredsOpt credsOpt = Kerberos.GetInitCredsOpt(ctx);
                    Kerberos.GetInitCredsOptSetCanonicalize(ctx, credsOpt, true);
                    using SafeKrb5Creds creds = Kerberos.GetInitCredsPassword(ctx, princ, credsOpt, password);
                    using SafeKrb5Ccache ccache = Kerberos.CCNewUnique(ctx, "MEMORY");
                    Kerberos.CCInitialize(ctx, ccache, princ);
                    Kerberos.CCStoreCred(ctx, ccache, creds);
                    ccacheName = $"{Kerberos.CCGetType(ctx, ccache)}:{Kerberos.CCGetName(ctx, ccache)}";
                }

                // The task runs in a separate thread and Krb5CCacheName affects the running thead only. Use the
                // prompter to set the default CCache to the in memory one when it is called.
                SaslPrompter prompter = new SaslPrompter(ccacheName);
                Task bindTask = OpenLDAP.SaslInteractiveBindAsync(ldap, "", AuthenticationMethod, prompter);
                bindTask.GetAwaiter().GetResult();
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

    internal class SaslPrompter : SaslInteract
    {
        public string? CCache { get; }

        public SaslPrompter(string? threadCCache) => CCache = threadCCache;

        public override string GetUser()
        {
            // This will be called by the same thread that gets the GSSAPI credential from the default ccache. By
            // calling this here we can use our explicit credential in a thread safe fashion.
            if (!string.IsNullOrEmpty(CCache))
                Gssapi.Krb5CCacheName(CCache);
            return ""; // The value here doesn't do anything
        }
    }
}
