using PSOpenAD.LDAP;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading;

namespace PSOpenAD;

internal class Operations
{
    /// <summary>Performs an LDAP search operation.</summary>
    /// <param name="connection">The LDAP connection to perform the search on on.</param>
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
        int searchId = connection.Session.SearchRequest(searchBase, scope, DereferencingPolicy.Never, sizeLimit,
            timeLimit / 1000, false, filter, attributes, controls);

        while (true)
        {
            LDAPMessage searchRes = connection.WaitForMessage(searchId, cancelToken: cancelToken);
            if (searchRes is SearchResultDone)
                break;
            else if (searchRes is SearchResultReference)
                continue;

            yield return (SearchResultEntry)searchRes;
        }
        connection.RemoveMessageQueue(searchId);
    }
}
