using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace PSOpenAD
{
    internal sealed class LibraryInfo : IDisposable
    {
        public string Id { get; }
        public string Path { get; }
        public IntPtr Handle { get; }

        public LibraryInfo(string id, string path)
        {
            Id = id;
            Path = path;
            Handle = NativeLibrary.Load(path);
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
                NativeLibrary.Free(Handle);
        }
        ~LibraryInfo() { Dispose(); }
    }

    internal sealed class NativeResolver : IDisposable
    {
        private readonly Dictionary<string, LibraryInfo> NativeHandles = new Dictionary<string, LibraryInfo>();

        public NativeResolver()
        {
            AssemblyLoadContext.Default.ResolvingUnmanagedDll += ImportResolver;
        }

        public bool CacheLibrary(string id, string path, string purpose, bool optional = false)
        {
            string? envOverride = Environment.GetEnvironmentVariable(id.ToUpperInvariant().Replace(".", "_"));
            if (!String.IsNullOrWhiteSpace(envOverride))
                path = envOverride;

            try
            {
                NativeHandles[id] = new LibraryInfo(id, path);
                return true;
            }
            catch (DllNotFoundException e)
            {
                if (!optional)
                    throw new DllNotFoundException($"Failed to load '{path}' for {purpose}", e);

                return false;
            }
        }

        private IntPtr ImportResolver(Assembly assembly, string libraryName)
        {
            if (NativeHandles.ContainsKey(libraryName))
                return NativeHandles[libraryName].Handle;

            return IntPtr.Zero;
        }

        public void Dispose()
        {
            foreach (KeyValuePair<string, LibraryInfo> native in NativeHandles)
                native.Value.Dispose();

            AssemblyLoadContext.Default.ResolvingUnmanagedDll -= ImportResolver;
            GC.SuppressFinalize(this);
        }
        ~NativeResolver() { Dispose(); }
    }

    public class OnModuleImportAndRemove : IModuleAssemblyInitializer, IModuleAssemblyCleanup
    {
        internal NativeResolver? Resolver;

        public void OnImport()
        {
            Resolver = new NativeResolver();
            Resolver.CacheLibrary(OpenLDAP.LIB_LDAP, "libldap.so", "LDAP connections");

            // The OpenLDAP may by linked with a custom path, the best we can do is search using the default name
            // for capability inspection. It's up to OpenLDAP to talk to SASL during the auth stage and report what
            // mechs are available.
            bool hasSasl = Resolver.CacheLibrary(CyrusSASL.LIB_SASL, "libsasl2.so", "SASL authentication", true);

            // While this is needed for Negotiate/Kerberos auth users can still use Simple auth so it's optional.
            bool hasGssapi = Resolver.CacheLibrary(GSSAPI.LIB_GSSAPI, "libgssapi_krb5.so.2", "GSSAPI authentication", true);

            // This is only used to lookup the default realm which is used to determine the default server.
            bool hasKrb5 = Resolver.CacheLibrary(Kerberos.LIB_KRB5, "libkrb5.so", "Kerberos authentication", true);

            // While channel binding isn't technically done by both these methods an Active Directory implementation
            // doesn't validate it's presence so from the purpose of a client it does work even if it's enforced on the
            // server end.
            GlobalState.Providers[AuthenticationMethod.Anonymous] = new AuthenticationProvider(
                AuthenticationMethod.Anonymous, "Anonymous", true, false, true, "");
            GlobalState.Providers[AuthenticationMethod.Simple] = new AuthenticationProvider(
                AuthenticationMethod.Simple, "Simple", true, false, true, "");

            // Even if SASL wasn't found this uses the OpenLDAP lib to report the mechs available. If SASL is
            // available we can get further details on the mechanism to provide a clearer picture of what it supports.
            List<string> saslMechs = OpenLDAP.GetOptionSaslMechList(new SafeLdapHandle());
            Dictionary<string, SaslClientMechanism> saslDetails = new Dictionary<string, SaslClientMechanism>();
            if (hasSasl && saslMechs.Count > 0)
            {
                CyrusSASL.ClientInit();
                CyrusSASL.ClientPluginInfo(String.Join(" ", saslMechs),
                    (SaslCallbackStage _, SaslClientMechanism? mech) =>
                    {
                        if (mech == null)
                            return;

                        saslDetails[mech.Plugin.MechName] = mech;
                    });
            }

            foreach (KeyValuePair<AuthenticationMethod, string> kvp in new Dictionary<AuthenticationMethod, string>()
            {
                { AuthenticationMethod.Kerberos, "GSSAPI" },
                { AuthenticationMethod.Negotiate, "GSS-SPNEGO" },
            })
            {
                bool present, canSign, supportsCB;
                present = canSign = supportsCB = false;
                string details = "";

                if (hasGssapi && saslMechs.Contains(kvp.Value))
                {
                    present = canSign = true;

                    SaslPluginFeatures? features = saslDetails.GetValueOrDefault(kvp.Value)?.Plugin.Features;
                    supportsCB = ((features ?? 0) & SaslPluginFeatures.SASL_FEAT_CHANNEL_BINDING) != 0;

                    if (!supportsCB)
                        details = "Older SASL library without CB support";
                }
                else if (!hasGssapi)
                {
                    details = "GSSAPI library not found";
                }
                else
                {
                    details = "SASL library not detected by OpenLDAP";

                }

                GlobalState.Providers[kvp.Key] = new AuthenticationProvider(kvp.Key, kvp.Value, present, canSign,
                    supportsCB, details);
            }

            // If the krb5 API is available, attempt to get the default realm used when creating an implicit session.
            if (GlobalState.Providers[AuthenticationMethod.Negotiate].Available && hasKrb5)
            {
                using SafeKrb5Context ctx = Kerberos.InitContext();
                try
                {
                    GlobalState.DefaultRealm = Kerberos.GetDefaultRealm(ctx);
                }
                catch (KerberosException) { }
            }
        }

        public void OnRemove(PSModuleInfo module)
        {
            foreach (OpenADSession session in GlobalState.ImplicitSessions.Values)
                session.Close();

            Resolver?.Dispose();
        }
    }
}
