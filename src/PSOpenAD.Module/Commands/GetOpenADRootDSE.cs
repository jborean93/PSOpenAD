using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADRootDSE"
)]
[OutputType(typeof(OpenADEntity))]
public class GetOpenADRootDSE : OpenADSessionCmdletBase
{
    [Parameter()]
    [Alias("Properties")]
    [ValidateNotNullOrEmpty]
    public string[]? Property { get; set; }

    private string[] _defaultAttributes = new[]
    {
        "configurationNamingContext",
        "currentTime",
        "defaultNamingContext",
        "dnsHostName",
        "domainControllerFunctionality",
        "domainFunctionality",
        "dsServiceName",
        "forestFunctionality",
        "highestCommittedUSN",
        "isGlobalCatalogReady",
        "isSynchronized",
        "ldapServiceName",
        "namingContexts",
        "rootDomainNamingContext",
        "schemaNamingContext",
        "serverName",
        "subschemaSubentry",
        "supportedCapabilities",
        "supportedControl",
        "supportedLDAPPolicies",
        "supportedLDAPVersion",
        "supportedSASLMechanisms",
    };

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        HashSet<string> requestedProps = _defaultAttributes
            .Union(Property ?? Array.Empty<string>())
            .ToHashSet();
        SearchResultEntry? searchRes = Operations.LdapSearchRequest(
            session.Connection,
            "",
            SearchScope.Base,
            0,
            session.OperationTimeout,
            new FilterPresent("objectClass"),
            requestedProps.ToArray(),
            controls: null,
            cancelToken: CancelToken,
            cmdlet: this,
            ignoreErrors: true
        ).FirstOrDefault();
        if (searchRes == null)
        {
            ErrorRecord err = new(
                new ItemNotFoundException("Cannot find AD RootDSE object"),
                "RootDSENotFound",
                ErrorCategory.ObjectNotFound,
                null);
            WriteError(err);
            return;
        }

        OpenADEntity rootDse = GetOpenADObject.CreateOutputObject(
            session,
            searchRes,
            requestedProps,
            static (a) => new OpenADEntity(a),
            this
        );
        WriteObject(rootDse);
    }
}
