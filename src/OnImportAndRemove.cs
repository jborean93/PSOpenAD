using DnsClient;
using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace PSOpenAD;

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
    private readonly Dictionary<string, LibraryInfo> NativeHandles = new();

    public NativeResolver()
    {
        AssemblyLoadContext.Default.ResolvingUnmanagedDll += ImportResolver;
    }

    public LibraryInfo? CacheLibrary(string id, string path)
    {
        string? envOverride = Environment.GetEnvironmentVariable(id.ToUpperInvariant().Replace(".", "_"));
        if (!String.IsNullOrWhiteSpace(envOverride))
            path = envOverride;

        try
        {
            NativeHandles[id] = new LibraryInfo(id, path);
            return NativeHandles[id];
        }
        catch (DllNotFoundException) { }

        return null;
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

        // GSSAPI is needed for Negotiate or Kerberos auth while Krb5 is used on non-Windows to locate the default
        // realm when setting up an implicit connection.
        LibraryInfo? gssapiLib = null;
        LibraryInfo? krb5Lib = null;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            // FUTURE: Only set this if the actual path wasn't overriden.
            GlobalState.GssapiProvider = GssapiProvider.GSSFramework;

            gssapiLib = Resolver.CacheLibrary(GSSAPI.LIB_GSSAPI, "/System/Library/Frameworks/GSS.framework/GSS");
            krb5Lib = Resolver.CacheLibrary(Kerberos.LIB_KRB5,
                "/System/Library/PrivateFrameworks/Heimdal.framework/Heimdal");
        }
        else if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            gssapiLib = Resolver.CacheLibrary(GSSAPI.LIB_GSSAPI, "libgssapi_krb5.so.2");
            krb5Lib = Resolver.CacheLibrary(Kerberos.LIB_KRB5, "libkrb5.so");
        }

        // While channel binding isn't technically done by both these methods an Active Directory implementation
        // doesn't validate it's presence so from the purpose of a client it does work even if it's enforced on the
        // server end.true
        GlobalState.Providers[AuthenticationMethod.Anonymous] = new(AuthenticationMethod.Anonymous, "ANONYMOUS",
            true, false, "");
        GlobalState.Providers[AuthenticationMethod.Simple] = new(AuthenticationMethod.Simple, "PLAIN", true,
            false, "");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            GlobalState.GssapiProvider = GssapiProvider.SSPI;

            GlobalState.Providers[AuthenticationMethod.Kerberos] = new(AuthenticationMethod.Kerberos, "GSSAPI",
                true, true, "");
            GlobalState.Providers[AuthenticationMethod.Negotiate] = new(AuthenticationMethod.Negotiate,
                "GSS-SPNEGO", true, true, "");

            // FUTURE: Add ad lookup.
        }
        else
        {
            if (GlobalState.GssapiProvider == GssapiProvider.None && gssapiLib != null)
            {
                GlobalState.GssapiProvider = GssapiProvider.Mit;
            }

            foreach (KeyValuePair<AuthenticationMethod, string> kvp in new Dictionary<AuthenticationMethod, string>()
            {
                { AuthenticationMethod.Kerberos, "GSSAPI" },
                { AuthenticationMethod.Negotiate, "GSS-SPNEGO" },
            })
            {
                bool present = false;
                bool canSign = false;
                string details = "";

                if (gssapiLib != null)
                {
                    present = canSign = true;
                }
                else
                {
                    details = "GSSAPI library not found";
                }

                GlobalState.Providers[kvp.Key] = new(kvp.Key, kvp.Value, present, canSign, details);
            }

            // If the krb5 API is available, attempt to get the default realm used when creating an implicit session.
            if (GlobalState.Providers[AuthenticationMethod.Negotiate].Available && krb5Lib != null)
            {
                if (NativeLibrary.TryGetExport(krb5Lib.Handle, "krb5_xfree", out var _))
                    GlobalState.GssapiProvider = GssapiProvider.Heimdal;

                string defaultRealm = "";
                using SafeKrb5Context ctx = Kerberos.InitContext();
                try
                {
                    defaultRealm = Kerberos.GetDefaultRealm(ctx);
                }
                catch (KerberosException) { }

                if (!string.IsNullOrWhiteSpace(defaultRealm))
                {
                    // _ldap._tcp.dc._msdcs.domain.com
                    string baseDomain = $"dc._msdcs.{defaultRealm}";
                    LookupClient dnsLookup = new();
                    ServiceHostEntry[] res = dnsLookup.ResolveService(baseDomain, "ldap",
                        System.Net.Sockets.ProtocolType.Tcp);

                    ServiceHostEntry? first = res.OrderByDescending(r => r.Weight).FirstOrDefault();
                    if (first != null)
                    {
                        GlobalState.DefaultDC = new($"ldap://{first.HostName}:{first.Port}/");
                    }
                }
            }
        }
    }

    public void OnRemove(PSModuleInfo module)
    {
        foreach (OpenADSession session in GlobalState.Sessions)
            session.Close();

        GlobalState.Sessions = new();
        Resolver?.Dispose();
    }
}
