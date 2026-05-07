using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using PSOpenAD.LDAP;

namespace PSOpenAD.Module.Commands;

public abstract class SetOpenADGroupMember : OpenADSessionCmdletBase
{
    internal static StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

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
    public SwitchParameter DisablePermissiveModify { get; set; }

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    internal abstract ModifyOperation ChangeOperation { get; }

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);
        ArgumentNullException.ThrowIfNull(Members);

        string? entry = Identity.DistinguishedName ?? GetIdentityDistinguishedName(Identity, session, "Set");
        if (string.IsNullOrEmpty(entry))
        {
            // Errors already written.
            return;
        }

        ModifyChange change = new(
            ChangeOperation,
            new(
                "member",
                SchemaMetadata.ConvertToRawAttributeCollection(
                    Members
                        .Select(m => m.DistinguishedName ?? GetIdentityDistinguishedName(m, session, "Member"))
                        .Where(dn => !string.IsNullOrEmpty(dn))!
                )
            )
        );

        List<LDAPControl>? serverControls = !DisablePermissiveModify ? new() { new PermissiveModify(false) } : null;

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
                serverControls,
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
}

[Cmdlet(
    VerbsCommon.Add, "OpenADGroupMember",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(void))]
public class AddOpenADGroupMember : SetOpenADGroupMember
{
    internal override ModifyOperation ChangeOperation => ModifyOperation.Add;
}

[Cmdlet(
    VerbsCommon.Remove, "OpenADGroupMember",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(void))]
public class RemoveOpenADGroupMember : SetOpenADGroupMember
{
    internal override ModifyOperation ChangeOperation => ModifyOperation.Delete;
}
