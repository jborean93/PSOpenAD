using PSOpenAD.LDAP;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading;

namespace PSOpenAD;

internal static class Operations
{
    /// <summary>Performs an LDAP search operation.</summary>
    /// <param name="connection">The LDAP connection to perform the search on.</param>
    /// <param name="searchBase">The search base of the query.</param>
    /// <param name="scope">The scope of the query.</param>
    /// <param name="sizeLimit"></param>
    /// <param name="timeLimit"></param>
    /// <param name="filter">The LDAP filter to use for the query.</param>
    /// <param name="attributes">The attributes to retrieve.</param>
    /// <param name="cancelToken">Token to cancel any network IO waits</param>
    /// <param name="cmdlet">The PSCmdlet that is running the operation</param>
    /// <returns>Yields each returned result containing the attributes requested from the search request.</returns>
    public static IEnumerable<SearchResultEntry> LdapSearchRequest(OpenADConnection connection, string searchBase,
        SearchScope scope, int sizeLimit, int timeLimit, LDAPFilter filter, string[] attributes,
        IList<LDAPControl>? controls, CancellationToken cancelToken, PSCmdlet? cmdlet)
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
                searchId = connection.Session.SearchRequest(searchBase, scope, DereferencingPolicy.Never, sizeLimit,
                    timeLimit / 1000, false, filter, attributes, copiedControls);

                request = false;
            }

            LDAPMessage searchRes = connection.WaitForMessage(searchId, cancelToken: cancelToken);
            if (searchRes is SearchResultDone resultDone)
            {
                PagedResultControl? paginateControl = resultDone.Controls?.OfType<PagedResultControl>().FirstOrDefault();
                if (resultDone.Result.ResultCode == LDAPResultCode.Success && paginateControl != null &&
                    paginateControl.Cookie?.Length > 0)
                {
                    cmdlet?.WriteVerbose("Receive pagination result, sending new search request");
                    request = true;
                    paginationCookie = paginateControl.Cookie;

                    continue;
                }
                else
                {
                    if (resultDone.Result.ResultCode == LDAPResultCode.SizeLimitExceeded)
                    {
                        cmdlet?.WriteWarning("Exceeded size limit of search request - results may be incomplete.");
                    }
                    break;
                }
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
