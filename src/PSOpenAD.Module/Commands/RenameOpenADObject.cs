using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Rename, "OpenADObject",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(OpenADObject))]
public class RenameOpenADObject : OpenADSessionCmdletBase
{
    private StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

    #region Rename-OpenAD* Parameters

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public ADObjectIdentity? Identity { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 1,
        ValueFromPipelineByPropertyName = true
    )]
    public string NewName { get; set; } = string.Empty;

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    #endregion

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);

        string? entry = Identity.DistinguishedName ?? GetIdentityDistinguishedName(Identity, session, "Rename");
        if (entry == null)
        {
            // Errors already written.
            return;
        }

        HashSet<string> searchProperties = OpenADObject.DEFAULT_PROPERTIES
            .Select(p => p.Item1)
            .ToHashSet(_caseInsensitiveComparer);

        DistinguishedName dn = DistinguishedName.Parse(entry);
        RelativeDistinguishedName newRDN = new(
            new AttributeTypeAndValue[] {
                new(dn.RelativeNames[0].Values[0].Type, NewName)
            });
        DistinguishedName newDN = new(new[] { newRDN }.Concat(dn.RelativeNames.Skip(1)).ToArray());

        SearchResultEntry? searchResult = null;
        WriteVerbose($"Renaming '{entry}' -> '{newDN}'");
        if (ShouldProcess($"'{entry}' -> '{newDN}'", "Rename"))
        {
            ModifyDNResponse resp = Operations.LdapModifyDNRequest(
                session.Connection,
                entry,
                newRDN.Values[0].ToString(),
                true,
                null,
                null,
                CancelToken,
                this);
            if (resp.Result.ResultCode != LDAPResultCode.Success)
            {
                return;
            }

            if (PassThru)
            {
                WriteVerbose($"Getting PassThru result for '{newDN}'");
                searchResult = Operations.LdapSearchRequest(
                    session.Connection,
                    newDN.ToString(),
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
            byte[][] emptyValue = SchemaMetadata.ConvertToRawAttributeCollection(string.Empty);
            PartialAttribute[] whatIfAttributes = searchProperties
                .Where(p => !(new[] { "distinguishedName", "name", "objectGUID" }).Contains(p))
                .Select(p => new PartialAttribute(p, emptyValue))
                .Union(new[]
                {
                    new PartialAttribute("distinguishedName", SchemaMetadata.ConvertToRawAttributeCollection(newDN.ToString())),
                    new PartialAttribute("name", SchemaMetadata.ConvertToRawAttributeCollection(NewName)),
                    new PartialAttribute("objectGUID", SchemaMetadata.ConvertToRawAttributeCollection(Guid.Empty)),
                }).ToArray();
            searchResult = new(0, null, newDN.ToString(), whatIfAttributes);
        }

        if (searchResult != null)
        {
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
}
