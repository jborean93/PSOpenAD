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
    /// <summary>Gets the default domain controller, looking it up if it has not been found yet.</summary>
    /// <remarks>
    /// A found DC is kept for the runspace. A failed lookup is not, it is written as an error record on the cmdlet
    /// and tried again next time, as the records may become reachable later, for example once a VPN is connected.
    /// An error recorded when the module was imported, like a missing Kerberos library, means there is nothing to
    /// look up and is written straight away.
    /// </remarks>
    /// <param name="state">The runspace state the found DC is kept in.</param>
    /// <param name="cmdlet">PSCmdlet to write the verbose and error records to.</param>
    /// <param name="defaultDC">The default DC if the method returns true.</param>
    /// <returns>True if the default DC was found, otherwise false.</returns>
    internal static bool TryGetDefaultDC(
        GlobalState state,
        PSCmdlet cmdlet,
        [NotNullWhen(true)] out Uri? defaultDC)
    {
        defaultDC = state.DefaultDC;
        if (defaultDC != null)
        {
            return true;
        }

        string? errorMessage = state.DefaultDCError;
        if (string.IsNullOrEmpty(errorMessage))
        {
            cmdlet.WriteVerbose("Looking up the default domain controller");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? TryLookupWindows(out defaultDC, out errorMessage)
                : TryLookupUnix(out defaultDC, out errorMessage))
            {
                state.DefaultDC = defaultDC;
                return true;
            }
        }

        cmdlet.WriteError(new ErrorRecord(
            new ArgumentException($"Cannot determine default realm for implicit domain controller. {errorMessage}"),
            "NoImplicitDomainController",
            ErrorCategory.InvalidArgument,
            null));
        return false;
    }

    private static bool TryLookupWindows(
        [NotNullWhen(true)] out Uri? defaultDC,
        [NotNullWhen(false)] out string? errorMessage)
    {
        defaultDC = null;
        errorMessage = null;

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
            errorMessage = $"Failure calling DsGetDcName to get default DC: {e.Message}";
            return false;
        }

        if (string.IsNullOrWhiteSpace(dcName))
        {
            errorMessage = "No configured default DC on host";
            return false;
        }

        defaultDC = new($"ldap://{dcName}:389/");
        return true;
    }

    private static bool TryLookupUnix(
        [NotNullWhen(true)] out Uri? defaultDC,
        [NotNullWhen(false)] out string? errorMessage)
    {
        defaultDC = null;

        if (!TryGetDefaultKerberosRealm(out var defaultRealm, out var realmException))
        {
            errorMessage = $"Failed to lookup krb5 default realm: {realmException}";
            return false;
        }

        // _ldap._tcp.dc._msdcs.domain.com
        string baseDomain = $"dc._msdcs.{defaultRealm}";
        LookupClient dnsLookup = new();
        try
        {
            ServiceHostEntry[] res = dnsLookup.ResolveService(baseDomain, "ldap",
                System.Net.Sockets.ProtocolType.Tcp);

            ServiceHostEntry? first = res.OrderBy(r => r.Priority).ThenBy(r => r.Weight).FirstOrDefault();
            if (first == null)
            {
                errorMessage = $"No SRV records for _ldap._tcp.{baseDomain} found";
                return false;
            }

            defaultDC = new($"ldap://{first.HostName}:{first.Port}/");
            errorMessage = null;
            return true;
        }
        catch (DnsResponseException e)
        {
            errorMessage = $"DNS Error looking up SRV records for _ldap._tcp.{baseDomain}: {e.Message}";
        }
        catch (Exception e)
        {
            errorMessage = $"Unknown error looking up SRV records for _ldap._tcp.{baseDomain}: {e.GetType().Name} - {e.Message}";
        }
        return false;
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
