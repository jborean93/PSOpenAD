using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading;

namespace PSOpenAD;

internal static class Operations
{
    /// <summary>Performs an LDAP add operation.</summary>
    /// <param name="connection">The LDAP connection to perform the add on.</param>
    /// <param name="entry">The entry DN to create the object at.</param>
    /// <param name="attributes">The attributes and their values to set on the new object.</param>
    /// <param name="controls">Custom controls to use with the request</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    /// <param name="cmdlet">The PSCmdlet that is running the operation.</param>
    /// <returns>The AddResponse from the request.</returns>
    public static AddResponse LdapAddRequest(
        IADConnection connection,
        string entry,
        PartialAttribute[] attributes,
        IList<LDAPControl>? controls,
        CancellationToken cancelToken,
        PSCmdlet? cmdlet
    )
    {
        cmdlet?.WriteVerbose($"Starting LDAP add request for '{entry}'");

        int addId = connection.Session.Add(entry, attributes, controls: controls);
        AddResponse addRes = (AddResponse)connection.WaitForMessage(addId, cancelToken: cancelToken);
        connection.RemoveMessageQueue(addId);

        if (addRes.Result.ResultCode != LDAPResultCode.Success)
        {
            ErrorRecord error = new(
                new LDAPException($"Failed to add '{entry}'", addRes.Result),
                "LDAPAddFailure",
                ErrorCategory.InvalidOperation,
                null);
            cmdlet?.WriteError(error);
        }

        return addRes;
    }

    /// <summary>Performs an LDAP delete operation.</summary>
    /// <param name="connection">The LDAP connection to perform the delete on.</param>
    /// <param name="entry">The entry DN to delete.</param>
    /// <param name="controls">Custom controls to use with the request</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    /// <param name="cmdlet">The PSCmdlet that is running the operation.</param>
    /// <returns>The DelResponse from the request.</returns>
    public static DelResponse LdapDeleteRequest(
        IADConnection connection,
        string entry,
        IList<LDAPControl>? controls,
        CancellationToken cancelToken,
        PSCmdlet? cmdlet
    )
    {
        cmdlet?.WriteVerbose($"Starting LDAP delete request for '{entry}'");

        int addId = connection.Session.Delete(entry, controls: controls);
        DelResponse delRes = (DelResponse)connection.WaitForMessage(addId, cancelToken: cancelToken);
        connection.RemoveMessageQueue(addId);

        if (delRes.Result.ResultCode != LDAPResultCode.Success)
        {
            ErrorRecord error = new(
                new LDAPException($"Failed to delete '{entry}'", delRes.Result),
                "LDAPDeleteFailure",
                ErrorCategory.InvalidOperation,
                null);
            cmdlet?.WriteError(error);
        }

        return delRes;
    }

    /// <summary>Performs an LDAP search operation.</summary>
    /// <param name="connection">The LDAP connection to perform the search on.</param>
    /// <param name="searchBase">The search base of the query.</param>
    /// <param name="scope">The scope of the query.</param>
    /// <param name="sizeLimit"></param>
    /// <param name="timeLimit"></param>
    /// <param name="filter">The LDAP filter to use for the query.</param>
    /// <param name="attributes">The attributes to retrieve.</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    /// <param name="cmdlet">The PSCmdlet that is running the operation.</param>
    /// <param name="ignoreErrors">Ignore errors and do not write to the error stream.</param>
    /// <returns>Yields each returned result containing the attributes requested from the search request.</returns>
    public static IEnumerable<SearchResultEntry> LdapSearchRequest(
        IADConnection connection,
        string searchBase,
        SearchScope scope,
        int sizeLimit,
        int timeLimit,
        LDAPFilter filter,
        string[] attributes,
        IList<LDAPControl>? controls,
        CancellationToken cancelToken,
        PSCmdlet? cmdlet,
        bool ignoreErrors
    )
    {
        cmdlet?.WriteVerbose($"Starting LDAP search request at '{searchBase}' for {scope} - {filter}");

        int searchId = 0;
        int paginationLimit = sizeLimit > 0 ? sizeLimit : 1000;
        byte[]? paginationCookie = null;
        bool request = true;

        while (true)
        {
            if (request)
            {
                List<LDAPControl> copiedControls = controls?.ToList() ?? new();
                copiedControls.Add(new PagedResultControl(false, paginationLimit, paginationCookie));
                searchId = connection.Session.Search(searchBase, scope, DereferencingPolicy.Never, sizeLimit,
                    timeLimit / 1000, false, filter, attributes, copiedControls);

                request = false;
            }

            LDAPMessage searchRes = connection.WaitForMessage(searchId, cancelToken: cancelToken);
            if (searchRes is SearchResultDone resultDone)
            {
                PagedResultControl? paginateControl = resultDone.Controls?.OfType<PagedResultControl>().FirstOrDefault();
                if (resultDone.Result.ResultCode == LDAPResultCode.Success && paginateControl?.Cookie?.Length > 0)
                {
                    cmdlet?.WriteVerbose("Receive pagination result, sending new search request");
                    request = true;
                    paginationCookie = paginateControl.Cookie;

                    continue;
                }
                else if (resultDone.Result.ResultCode == LDAPResultCode.SizeLimitExceeded)
                {
                    cmdlet?.WriteWarning("Exceeded size limit of search request - results may be incomplete.");
                }
                else if (!ignoreErrors && resultDone.Result.ResultCode == LDAPResultCode.Referral)
                {
                    // FUTURE: see if we can try and do the referral ourselves
                    ErrorRecord error = new(
                        new LDAPException(resultDone.Result),
                        "LDAPReferral",
                        ErrorCategory.ResourceUnavailable,
                        null);

                    string referralUris = string.Join("', '", resultDone.Result.Referrals ?? Array.Empty<string>());
                    error.ErrorDetails = new(
                        $"A referral was returned from the server that points to: '{referralUris}'");
                    error.ErrorDetails.RecommendedAction = "Perform request on one of the referral URIs";
                    cmdlet?.WriteError(error);
                }
                else if (!ignoreErrors && resultDone.Result.ResultCode != LDAPResultCode.Success)
                {
                    ErrorRecord error = new(
                        new LDAPException(resultDone.Result),
                        "LDAPSearchFailure",
                        ErrorCategory.InvalidOperation,
                        null);
                    cmdlet?.WriteError(error);
                }
                break;
            }
            else if (searchRes is SearchResultReference)
            {
                continue;
            }

            yield return (SearchResultEntry)searchRes;
        }
        connection.RemoveMessageQueue(searchId);
    }
}
