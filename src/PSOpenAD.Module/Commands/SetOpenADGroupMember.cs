using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using PSOpenAD.LDAP;

namespace PSOpenAD.Module.Commands;

public abstract class SetOpenADGroupMember : OpenADSessionCmdletBase
{
    internal static StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

    internal static LDAPFilter _filteredClass = new FilterEquality("objectCategory", LDAPFilter.EncodeSimpleFilterValue("group"));

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public ADPrincipalIdentity? Identity { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 1
    )]
    public ADPrincipalIdentity[]? Members { get; set; }

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);
        ArgumentNullException.ThrowIfNull(Members);

        WriteVerbose($"Attempting to get distinguishedName and member for group with filter '{Identity.LDAPFilter}'");

        SearchResultEntry? entryResult = Operations.LdapSearchRequest(
            session.Connection,
            Identity.DistinguishedName ?? session.DefaultNamingContext,
            SearchScope.Subtree,
            0,
            session.OperationTimeout,
            new FilterAnd(new[] { _filteredClass, Identity.LDAPFilter }),
            new[] { "distinguishedName", "member" },
            null,
            CancelToken,
            this,
            false
        ).FirstOrDefault();

        string? entry = entryResult?.Attributes
            .Where(a => a.Name == "distinguishedName")
            .Select(dn => SyntaxDefinition.ReadDN(dn.Values[0]))
            .FirstOrDefault();

        if (entryResult == null || string.IsNullOrEmpty(entry))
        {
            ErrorRecord error = new(
                new ArgumentException($"Failed to find group to set using the filter '{Identity.LDAPFilter}'"),
                "CannotFindSetObjectWithFilter",
                ErrorCategory.InvalidArgument,
                Identity
            );
            WriteError(error);
            return;
        }

        ModifyChange change = new(
            ModifyOperation.Replace,
            new(
                "member",
                SchemaMetadata.ConvertToRawAttributeCollection(
                    FilterMembers(
                        entryResult.Attributes
                            .Where(a => a.Name == "member")
                            .SelectMany(a => a.Values)
                            .Select(b => SyntaxDefinition.ReadDN(b)),
                        Members
                            .Select(m => m.DistinguishedName ?? GetIdentityDistinguishedName(m, session, "Member"))
                            .Where(dn => !string.IsNullOrEmpty(dn))!
                    )
                )
            )
        );

        HashSet<string> searchProperties = OpenADObject.DEFAULT_PROPERTIES
            .Select(p => p.Item1)
            .ToHashSet(_caseInsensitiveComparer);

        SearchResultEntry? searchResult = null;
        if (ShouldProcess(entry, "Set"))
        {
            WriteVerbose($"Setting LDAP object '{entry}'");
            ModifyResponse resp = Operations.LdapModifyRequest(
                session.Connection,
                entry,
                new[] { change },
                null,
                CancelToken,
                this
            );
            if (resp.Result.ResultCode != LDAPResultCode.Success)
            {
                return;
            }

            if (PassThru)
            {
                WriteVerbose($"Getting PassThru result for '{entry}'");
                searchResult = Operations.LdapSearchRequest(
                    session.Connection,
                    entry,
                    SearchScope.Base,
                    0,
                    session.OperationTimeout,
                    new FilterPresent("objectClass"),
                    searchProperties.ToArray(),
                    null,
                    CancelToken,
                    this,
                    false
                ).FirstOrDefault()!;
            }
        }
        else if (PassThru)
        {
            // When using -WhatIf with -PassThru a dummy result is used to build the final object.
            byte[][] emptyValue = SchemaMetadata.ConvertToRawAttributeCollection(string.Empty);
            PartialAttribute[] whatIfAttributes = searchProperties
                .Where(p => !(new[] { "distinguishedName", "name", "objectGUID" }).Contains(p))
                .Select(p => new PartialAttribute(p, emptyValue))
                .Union(new[]
                {
                    new PartialAttribute("distinguishedName", SchemaMetadata.ConvertToRawAttributeCollection(entry)),
                    new PartialAttribute("name", emptyValue),
                    new PartialAttribute("objectGUID", SchemaMetadata.ConvertToRawAttributeCollection(Guid.Empty)),
                }).ToArray();
            searchResult = new(0, null, entry, whatIfAttributes);
        }

        if (searchResult == null)
        {
            return;
        }

        OpenADEntity resultObj = GetOpenADObject.CreateOutputObject(
            session,
            searchResult,
            searchProperties,
            null,
            this
        );
        WriteObject(resultObj);
    }

    abstract internal IEnumerable<string> FilterMembers(IEnumerable<string> first, IEnumerable<string> second);
}

[Cmdlet(
    VerbsCommon.Add, "OpenADGroupMember",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(void))]
public class AddOpenADGroupMember : SetOpenADGroupMember
{
    internal override IEnumerable<string> FilterMembers(IEnumerable<string> first, IEnumerable<string> second)
    {
        return first.Union(second, _caseInsensitiveComparer);
    }
}

[Cmdlet(
    VerbsCommon.Remove, "OpenADGroupMember",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(void))]
public class RemoveOpenADGroupMember : SetOpenADGroupMember
{
    internal override IEnumerable<string> FilterMembers(IEnumerable<string> first, IEnumerable<string> second)
    {
        return first.Except(second, _caseInsensitiveComparer);
    }
}
