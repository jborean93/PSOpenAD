using DnsClient;
using PSOpenAD.Native;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Loader;

namespace PSOpenAD.Module;

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

    public LibraryInfo? CacheLibrary(string id, string[] paths)
    {
        string? envOverride = Environment.GetEnvironmentVariable(id.ToUpperInvariant().Replace(".", "_"));
        if (!String.IsNullOrWhiteSpace(envOverride))
            paths = new[] { envOverride };

        foreach (string libPath in paths)
        {
            try
            {
                NativeHandles[id] = new LibraryInfo(id, libPath);
                return NativeHandles[id];
            }
            catch (DllNotFoundException) { }
        }

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
    internal const string MACOS_GSS_FRAMEWORK = "/System/Library/Frameworks/GSS.framework/GSS";

    internal NativeResolver? Resolver;

    public void OnImport()
    {
        Resolver = new NativeResolver();

        GlobalState state = GlobalState.GetFromTLS();

        // While channel binding isn't technically done by both these methods an Active Directory implementation
        // doesn't validate it's presence so from the purpose of a client it does work even if it's enforced on the
        // server end.
        state.Providers[AuthenticationMethod.Anonymous] = new(AuthenticationMethod.Anonymous, "ANONYMOUS",
            true, false, "");
        state.Providers[AuthenticationMethod.Simple] = new(AuthenticationMethod.Simple, "PLAIN", true,
            false, "");
        state.Providers[AuthenticationMethod.Certificate] = new(AuthenticationMethod.Certificate, "EXTERNAL",
            true, true, "");

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Windows always has SSPI available.
            state.GssapiProvider = GssapiProvider.SSPI;
            state.Providers[AuthenticationMethod.Kerberos] = new(AuthenticationMethod.Kerberos, "GSSAPI",
                true, true, "");
            state.Providers[AuthenticationMethod.Negotiate] = new(AuthenticationMethod.Negotiate,
                "GSS-SPNEGO", true, true, "");

            const GetDcFlags getDcFlags = GetDcFlags.DS_IS_DNS_NAME | GetDcFlags.DS_ONLY_LDAP_NEEDED |
                GetDcFlags.DS_RETURN_DNS_NAME | GetDcFlags.DS_WRITABLE_REQUIRED;
            string? dcName = null;
            try
            {
                DCInfo dcInfo = NetApi32.DsGetDcName(null, null, null, getDcFlags, null);
                dcName = dcInfo.Name?.TrimStart('\\');
            }
            catch (Win32Exception e) when (e.NativeErrorCode == 1355) // ERROR_NO_SUCH_DOMAIN
            {
                // While it's questionable why you would use this module if it hasn't been joined to a domain it's
                // still possible to use this for any LDAP server on Windows so just ignore the default DC setup.
            }
            catch (Exception e)
            {
                state.DefaultDCError = $"Failure calling DsGetDcName to get default DC: {e.Message}";
            }

            if (!string.IsNullOrWhiteSpace(dcName))
            {
                state.DefaultDC = new($"ldap://{dcName}:389/");
            }
            else if (string.IsNullOrEmpty(state.DefaultDCError))
            {
                state.DefaultDCError = "No configured default DC on host";
            }
        }
        else
        {
            state.GssapiProvider = GssapiProvider.None;
            LibraryInfo? gssapiLib = Resolver.CacheLibrary(GSSAPI.LIB_GSSAPI, new[] {
                MACOS_GSS_FRAMEWORK, // macOS GSS Framework (technically Heimdal)
                "libgssapi_krb5.so.2", // MIT krb5
                "libgssapi.so.3", "libgssapi.so", // Heimdal
            });
            LibraryInfo? krb5Lib = Resolver.CacheLibrary(Kerberos.LIB_KRB5, new[] {
                "/System/Library/PrivateFrameworks/Heimdal.framework/Heimdal", // macOS Heimdal Framework
                "libkrb5.so.3", // MIT krb5
                "libkrb5.so.26", "libkrb5.so", // Heimdal
            });

            if (gssapiLib == null)
            {
                state.Providers[AuthenticationMethod.Kerberos] = new(AuthenticationMethod.Kerberos,
                    "GSSAPI", false, false, "GSSAPI library not found");
                state.Providers[AuthenticationMethod.Negotiate] = new(AuthenticationMethod.Negotiate,
                    "GSS-SPNEGO", false, false, "GSSAPI library not found");

                state.DefaultDCError = "Failed to find GSSAPI library";
            }
            else
            {
                state.Providers[AuthenticationMethod.Kerberos] = new(AuthenticationMethod.Kerberos,
                    "GSSAPI", true, true, "");
                state.Providers[AuthenticationMethod.Negotiate] = new(AuthenticationMethod.Negotiate,
                    "GSS-SPNEGO", true, true, "");

                if (gssapiLib.Path == MACOS_GSS_FRAMEWORK)
                {
                    state.GssapiProvider = GssapiProvider.GSSFramework;
                }
                else if (NativeLibrary.TryGetExport(gssapiLib.Handle, "krb5_xfree", out var _))
                {
                    // While technically exported by the krb5 lib the Heimdal GSSAPI lib depends on it so the same
                    // symbol will be exported there and we can use that to detect if Heimdal is in use.
                    state.GssapiProvider = GssapiProvider.Heimdal;
                }
                else
                {
                    state.GssapiProvider = GssapiProvider.MIT;
                }

                // If the krb5 API is available, attempt to get the default realm used when creating an implicit
                // session.
                if (krb5Lib != null)
                {
                    if (TryGetDefaultKerberosRealm(out var defaultRealm, out var realmException))
                    {
                        // _ldap._tcp.dc._msdcs.domain.com
                        string baseDomain = $"dc._msdcs.{defaultRealm}";
                        LookupClient dnsLookup = new();
                        try
                        {
                            ServiceHostEntry[] res = dnsLookup.ResolveService(baseDomain, "ldap",
                                System.Net.Sockets.ProtocolType.Tcp);

                            ServiceHostEntry? first = res.OrderBy(r => r.Priority).ThenBy(r => r.Weight).FirstOrDefault();
                            if (first != null)
                            {
                                state.DefaultDC = new($"ldap://{first.HostName}:{first.Port}/");
                            }
                            else
                            {
                                state.DefaultDCError = $"No SRV records for _ldap._tcp.{baseDomain} found";
                            }
                        }
                        catch (DnsResponseException e)
                        {
                            state.DefaultDCError = $"DNS Error looking up SRV records for _ldap._tcp.{baseDomain}: {e.Message}";
                        }
                        catch (Exception e)
                        {
                            state.DefaultDCError = $"Unknown error looking up SRV records for _ldap._tcp.{baseDomain}: {e.GetType().Name} - {e.Message}";
                        }
                    }
                    else
                    {
                        state.DefaultDCError = $"Failed to lookup krb5 default realm: {realmException}";
                    }
                }
                else
                {
                    state.DefaultDCError = "Failed to find Kerberos library";
                }
            }
        }
    }

    public void OnRemove(PSModuleInfo module)
    {
        GlobalState state = GlobalState.GetFromTLS();
        foreach (OpenADSession session in state.Sessions)
            session.Close();

        state.Sessions = new();
        Resolver?.Dispose();
    }

    /// <summary>
    /// Attempt to get the default Kerberos realm from the system for the DC lookup.
    /// </summary>
    /// <param name="realm">The realm if the method returns true.</param>
    /// <param name="errorMessage">The error details if the method returns false.</param>
    /// <returns>True if the realm was successfully retrieved, otherwise false.</returns>
    private static bool TryGetDefaultKerberosRealm(
        [NotNullWhen(true)] out string? realm,
        [NotNullWhen(false)] out string? errorMessage)
    {
        realm = null;
        errorMessage = null;

        using var ctx = Kerberos.InitContext();
        if (Kerberos.TryGetDefaultRealm(ctx, out realm, out var defaultRealmException))
        {
            return true;
        }

        if (!Kerberos.TryGetDefaultCCache(ctx, out var ccache, out var defaultCCException))
        {
            errorMessage = $"{defaultRealmException.Message}, {defaultCCException.Message}";
            return false;
        }
        using (ccache)
        {
            if (!Kerberos.TryGetCCachePrincipal(ctx, ccache, out var principal, out var defaultCCPrincipalException))
            {
                errorMessage = $"{defaultRealmException.Message}, {defaultCCPrincipalException.Message}";
                return false;
            }

            using (principal)
            {
                if (Kerberos.TryUnparseName(ctx, principal, out var principalName, out var defaultUnparseException))
                {
                    int realmIdx = principalName.IndexOf('@');
                    if (realmIdx != -1)
                    {
                        realm = principalName[(realmIdx + 1)..];
                        return true;
                    }
                    else
                    {
                        errorMessage = $"{defaultRealmException.Message}, failed to find principal realm in name '{principalName}'";
                        return false;
                    }
                }
                else
                {
                    errorMessage = $"{defaultRealmException.Message}, {defaultUnparseException.Message}";
                    return false;
                }
            }
        }
    }
}
