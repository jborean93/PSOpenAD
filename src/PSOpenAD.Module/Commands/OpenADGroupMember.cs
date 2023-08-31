using PSOpenAD.LDAP;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Threading;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADGroupMember",
    DefaultParameterSetName = "ServerIdentity"
)]
[OutputType(typeof(OpenADPrincipal))]
public class GetOpenADGroupMember : GetOpenADOperation<ADPrincipalIdentity>
{
    private string _currentGroupDN = "";

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
            SearchScope, 1, session.OperationTimeout, filter, new[] { "primaryGroupToken" }, serverControls,
            cancelToken, this, false))
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

            // Objects don't include their primary group in their memberOf attribute,
            // instead the group's RID is in the user's primaryGroupID attribute.
            // Get the group's RID from its primaryGroupToken attribute and add to the filter.
            // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/cc24555b-61c7-49a2-9748-167b8ce5a512)
            string? primaryGroupToken = group.Attributes
                .Where(a => a.Name == "primaryGroupToken")
                .Select(a => SyntaxDefinition.ReadInteger(a.Values[0]).ToString())
                .FirstOrDefault();

            if (!string.IsNullOrWhiteSpace(primaryGroupToken))
            {
                memberOfFilter = new FilterOr(new[] {
                    memberOfFilter,
                    new FilterEquality("primaryGroupID", LDAP.LDAPFilter.EncodeSimpleFilterValue(primaryGroupToken))
                });
            }

            _currentGroupDN = group.ObjectName;
            try
            {
                foreach (SearchResultEntry result in Operations.LdapSearchRequest(session.Connection, searchBase,
                    SearchScope, 0, session.OperationTimeout, memberOfFilter, attributes, serverControls, cancelToken,
                    this, false))
                {
                    yield return result;
                }
            }
            finally
            {
                _currentGroupDN = "";
            }
        }
    }

    internal override void ProcessOutputObject(PSObject obj)
    {
        obj.Properties.Add(new PSNoteProperty("QueriedGroup", _currentGroupDN));
    }
}
