using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Move, "OpenADObject",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(OpenADObject))]
public class MoveOpenADObject : OpenADSessionCmdletBase
{
    private StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

    #region Move-OpenAD* Parameters

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
    public string TargetPath { get; set; } = string.Empty;

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    #endregion

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);

        string? entry = Identity.DistinguishedName ?? GetIdentityDistinguishedName(Identity, session, "Move");
        if (entry == null)
        {
            // Errors already written.
            return;
        }

        HashSet<string> searchProperties = OpenADObject.DEFAULT_PROPERTIES
            .Select(p => p.Item1)
            .ToHashSet(_caseInsensitiveComparer);

        DistinguishedName dn = DistinguishedName.Parse(entry);
        DistinguishedName newRootDN = DistinguishedName.Parse(TargetPath);
        RelativeDistinguishedName originalRDN = dn.RelativeNames[0];
        DistinguishedName newDN = new(new[] { originalRDN }.Concat(newRootDN.RelativeNames).ToArray());

        SearchResultEntry? searchResult = null;
        WriteVerbose($"Moving '{entry}' -> '{newDN}'");
        if (ShouldProcess($"'{entry}' -> '{newDN}'", "Rename"))
        {
            ModifyDNResponse resp = Operations.LdapModifyDNRequest(
                session.Connection,
                entry,
                originalRDN.ToString(),
                true,
                TargetPath,
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
            string entryName = originalRDN.Values[0].Value;
            byte[][] emptyValue = SchemaMetadata.ConvertToRawAttributeCollection(string.Empty);
            PartialAttribute[] whatIfAttributes = searchProperties
                .Where(p => !(new[] { "distinguishedName", "name", "objectGUID" }).Contains(p))
                .Select(p => new PartialAttribute(p, emptyValue))
                .Union(new[]
                {
                    new PartialAttribute("distinguishedName", SchemaMetadata.ConvertToRawAttributeCollection(newDN)),
                    new PartialAttribute("name", SchemaMetadata.ConvertToRawAttributeCollection(entryName)),
                    new PartialAttribute("objectGUID", SchemaMetadata.ConvertToRawAttributeCollection(Guid.Empty)),
                }).ToArray();
            searchResult = new(0, null, entry, whatIfAttributes);
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
