using PSOpenAD.LDAP;
using PSOpenAD.Security;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading;

namespace PSOpenAD.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADGroupMember",
    DefaultParameterSetName = "ServerIdentity"
)]
[OutputType(typeof(OpenADPrincipal))]
public class GetOpenADGroupMember : GetOpenADOperation<ADPrincipalIdentity>
{
    [Parameter()]
    public SwitchParameter Recursive { get; set; }

    internal override (string, bool)[] DefaultProperties => OpenADPrincipal.DEFAULT_PROPERTIES;

    internal override LDAPFilter FilteredClass
        => new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("group"));

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADPrincipal(attributes);

    internal override IEnumerable<SearchResultEntry> SearchRequest(OpenADSession session, string searchBase,
        LDAP.LDAPFilter filter, string[] attributes, IList<LDAPControl>? serverControls, CancellationToken cancelToken)
    {
        foreach (SearchResultEntry group in Operations.LdapSearchRequest(session.Connection, searchBase,
            SearchScope, 1, session.OperationTimeout, filter, new[] { "objectSid" }, serverControls, cancelToken, this,
            false))
        {
            // use memberOf rather than member to make recursive search easier & avoid paging
            LDAPFilter memberOfFilter;
            if (Recursive)
            {
                // Manually recursing into groups would also work, not sure where perf sweet spot is.
                // Exclude groups to match Get-ADGroupMembership results. Including only objectClass=user works too.
                memberOfFilter = new FilterAnd(new LDAPFilter[] {
                        new FilterNot(
                            new FilterEquality("objectCategory", LDAP.LDAPFilter.EncodeSimpleFilterValue("group"))
                        ),
                        new FilterExtensibleMatch("1.2.840.113556.1.4.1941", "memberOf",
                            LDAP.LDAPFilter.EncodeSimpleFilterValue(group.ObjectName), false)
                    });
            }
            else
            {
                memberOfFilter = new FilterEquality("memberOf",
                    LDAP.LDAPFilter.EncodeSimpleFilterValue(group.ObjectName));
            }

            // get group's rid and include (primaryGroupID=$RID) for primary groups. Only on user so no recursion.
            // objectSid is most likely going to be there but it's optionally added to satisfy dotnet's null checks.
            SecurityIdentifier? sid = group.Attributes
                .Where(a => a.Name == "objectSid")
                .Select(a => new SecurityIdentifier(a.Values[0]))
                .FirstOrDefault();

            if (sid != null)
            {
                string rid = sid.ToString().Split("-").Last();

                memberOfFilter = new FilterOr(new[] {
                    memberOfFilter,
                    new FilterEquality("primaryGroupID", LDAP.LDAPFilter.EncodeSimpleFilterValue(rid))
                });
            }

            foreach (SearchResultEntry result in Operations.LdapSearchRequest(session.Connection, searchBase,
                SearchScope, 0, session.OperationTimeout, memberOfFilter, attributes, serverControls, cancelToken,
                this, false))
            {
                yield return result;
            }
        }
    }
}
