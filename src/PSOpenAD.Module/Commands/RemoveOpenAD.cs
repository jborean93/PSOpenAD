using PSOpenAD.LDAP;
using System;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Remove, "OpenADObject",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
public class RemoveOpenADObject : OpenADSessionCmdletBase
{
    #region Remove-OpenAD* Parameters

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public ADObjectIdentity? Identity { get; set; }

    #endregion

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);

        string entryDN;
        if (string.IsNullOrWhiteSpace(Identity.DistinguishedName))
        {
            WriteVerbose($"Looking up distinguished name for Identity object with filter '{Identity.LDAPFilter}'");
            SearchResultEntry? searchRes = Operations.LdapSearchRequest(
                session.Connection,
                session.DefaultNamingContext,
                SearchScope.Subtree,
                0,
                session.OperationTimeout,
                Identity.LDAPFilter,
                Array.Empty<string>(),
                controls: null,
                cancelToken: CancelToken,
                cmdlet: this,
                ignoreErrors: false
            ).FirstOrDefault();

            if (searchRes != null)
            {
                WriteVerbose($"Found LDAP object to delete '{searchRes.ObjectName}'");
                entryDN = searchRes.ObjectName;
            }
            else
            {
                ErrorRecord err = new(
                    new ArgumentException($"Failed to find object for deletion with the filter '{Identity.LDAPFilter}'"),
                    "LDAPFindDNForDeleteFailure",
                    ErrorCategory.InvalidArgument,
                    Identity.LDAPFilter.ToString()
                );
                WriteError(err);
                return;
            }
        }
        else
        {
            WriteVerbose($"Using distinguished name from Identity object '{Identity.DistinguishedName}'");
            entryDN = Identity.DistinguishedName;
        }

        if (ShouldProcess(entryDN, "Delete"))
        {
            WriteVerbose($"Removing LDAP object '{entryDN}'");
            Operations.LdapDeleteRequest(
                session.Connection,
                entryDN,
                controls: null,
                cancelToken: CancelToken,
                cmdlet: this
            );
        }
    }
}
