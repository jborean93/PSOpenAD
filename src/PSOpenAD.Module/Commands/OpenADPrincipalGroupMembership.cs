using PSOpenAD.LDAP;
using PSOpenAD.Security;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADPrincipalGroupMembership",
    DefaultParameterSetName = "ServerIdentity"
)]
[OutputType(typeof(OpenADGroup))]
public class GetOpenADPrincipalGroupMembership : GetOpenADOperation<ADPrincipalIdentity>
{
    private string _currentPrincipalDN = "";

    [Parameter()]
    public SwitchParameter Recursive { get; set; }

    internal override (string, bool)[] DefaultProperties => OpenADGroup.DEFAULT_PROPERTIES;

    internal override LDAPFilter FilteredClass => new FilterPresent("objectSid");

    internal override OpenADObject CreateADObject(Dictionary<string, (PSObject[], bool)> attributes)
        => new OpenADGroup(attributes);

    internal override IEnumerable<SearchResultEntry> SearchRequest(
        OpenADSession session,
        string searchBase,
        LDAPFilter filter,
        string[] attributes,
        IList<LDAPControl>? serverControls
    )
    {
        foreach (SearchResultEntry principal in Operations.LdapSearchRequest(session.Connection, searchBase,
            SearchScope, 1, session.OperationTimeout, filter, new[] { "memberOf", "objectSid", "primaryGroupID" },
            serverControls, CancelToken, this, false))
        {
            FilterEquality? primaryGroupFilter = null;
            LDAPFilter groupMembershipFilter;

            if (Recursive) {
                groupMembershipFilter = new FilterExtensibleMatch("1.2.840.113556.1.4.1941", "member",
                    LDAP.LDAPFilter.EncodeSimpleFilterValue(principal.ObjectName), false);
            } else {
                groupMembershipFilter = new FilterEquality("member",
                    LDAP.LDAPFilter.EncodeSimpleFilterValue(principal.ObjectName));
            }

            SecurityIdentifier objectSid = new SecurityIdentifier(principal.Attributes
                .Where(a => a.Name == "objectSid")
                .Select(a => a.Values[0])
                .FirstOrDefault());

            // Objects don't include their primary group in their memberOf attribute,
            // instead the group's RID is in the object's primaryGroupID attribute.
            // We can't query for groups with a matching primaryGroupToken as it's a constructed attribute,
            // so get the group's SID by swapping the RID in the object's SID.
            // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/cc24555b-61c7-49a2-9748-167b8ce5a512)
            string? primaryGroupId = principal.Attributes
                .Where(a => a.Name == "primaryGroupID")
                .Select(a => SyntaxDefinition.ReadInteger(a.Values[0]).ToString())
                .FirstOrDefault();

            if (!string.IsNullOrWhiteSpace(primaryGroupId))
            {
                string[] splitSid = objectSid.ToString().Split('-');
                splitSid[splitSid.Length-1] = primaryGroupId;
                string primaryGroupSid = string.Join('-', splitSid);
                primaryGroupFilter =
                    new FilterEquality("objectSid", LDAP.LDAPFilter.EncodeSimpleFilterValue(primaryGroupSid));
            }

            if (primaryGroupFilter != null) {
                groupMembershipFilter = new FilterOr(new LDAPFilter[] {primaryGroupFilter, groupMembershipFilter});
            }

            _currentPrincipalDN = principal.ObjectName;

            try
            {
                foreach (SearchResultEntry result in Operations.LdapSearchRequest(session.Connection, searchBase,
                    SearchScope, 0, session.OperationTimeout, groupMembershipFilter, attributes, serverControls,
                    CancelToken, this, false))
                {
                    yield return result;
                }
            }
            finally
            {
                _currentPrincipalDN = "";
            }
        }
    }

    internal override void ProcessOutputObject(PSObject obj)
    {
        obj.Properties.Add(new PSNoteProperty("QueriedPrincipal", _currentPrincipalDN));
    }
}
