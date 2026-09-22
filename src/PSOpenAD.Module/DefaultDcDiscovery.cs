using DnsClient;
using PSOpenAD.Native;
using System;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace PSOpenAD.Module;

/// <summary>
/// Finds the default domain controller used for implicit sessions. On Windows this is DsGetDcName, elsewhere the
/// krb5 default realm and a DNS SRV lookup for it. Both can block for a long time when the records are not
/// reachable, so the lookup is done the first time a default DC is needed rather than when the module is imported.
/// </summary>
internal static class DefaultDcDiscovery
{
    /// <summary>Does the default DC lookup if it has not already been done for this runspace.</summary>
    /// <param name="state">The runspace state the result is stored in.</param>
    /// <param name="cmdlet">PSCmdlet to write verbose records to.</param>
    internal static void Ensure(GlobalState state, PSCmdlet cmdlet)
    {
        if (state.DefaultDCLookupDone)
        {
            return;
        }

        cmdlet.WriteVerbose("Looking up the default domain controller");
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                LookupWindows(state);
            }
            else
            {
                LookupUnix(state);
            }
        }
        finally
        {
            state.DefaultDCLookupDone = true;
        }
    }

    private static void LookupWindows(GlobalState state)
    {
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

    private static void LookupUnix(GlobalState state)
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
