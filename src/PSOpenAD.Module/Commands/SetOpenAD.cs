using PSOpenAD.LDAP;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Set, "OpenADObject",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(OpenADObject))]
public class SetOpenADObject : OpenADSessionCmdletBase
{
    private StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

    #region Set-OpenAD* Parameters

    [Parameter]
    public IDictionary? Add { get; set; }

    [Parameter]
    public string[] Clear { get; set; } = Array.Empty<string>();

    [Parameter]
    public string? Description { get; set; }

    [Parameter]
    public string? DisplayName { get; set; }

    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public ADObjectIdentity? Identity { get; set; }

    [Parameter]
    public IDictionary? Remove { get; set; }

    [Parameter]
    public IDictionary? Replace { get; set; }

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    #endregion

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);

        string? entry = Identity.DistinguishedName ?? GetIdentityDistinguishedName(Identity, session, "Set");
        if (entry == null)
        {
            // Errors already written.
            return;
        }

        List<ModifyChange> changes = new();
        if (Remove != null)
        {
            changes.AddRange(ProcessChanges(ModifyOperation.Delete, Remove, nameof(Remove)));
        }
        if (Add != null)
        {
            changes.AddRange(ProcessChanges(ModifyOperation.Add, Add, nameof(Add)));
        }
        if (Replace != null)
        {
            changes.AddRange(ProcessChanges(ModifyOperation.Replace, Replace, nameof(Replace)));
        }
        foreach (string toClear in Clear)
        {
            changes.Add(new ModifyChange(
                ModifyOperation.Replace,
                new PartialAttribute(toClear, Array.Empty<byte[]>())));
        }

        HashSet<string> requestedAttributes = changes
            .Select(c => c.Modification.Name)
            .ToHashSet(_caseInsensitiveComparer);
        if (!string.IsNullOrWhiteSpace(Description) && requestedAttributes.Add("description"))
        {
            changes.Add(new(
                ModifyOperation.Replace,
                new("description", SchemaMetadata.ConvertToRawAttributeCollection(Description))));
        }

        if (!string.IsNullOrWhiteSpace(DisplayName) && requestedAttributes.Add("displayName"))
        {
            changes.Add(new(
                ModifyOperation.Replace,
                new("displayName", SchemaMetadata.ConvertToRawAttributeCollection(DisplayName))));
        }

        HashSet<string> searchProperties = OpenADObject.DEFAULT_PROPERTIES
            .Select(p => p.Item1)
            .Union(requestedAttributes)
            .ToHashSet(_caseInsensitiveComparer);

        SearchResultEntry? searchResult = null;
        if (ShouldProcess(entry, "Set"))
        {
            WriteVerbose($"Setting LDAP object '{entry}'");
            ModifyResponse resp = Operations.LdapModifyRequest(
                session.Connection,
                entry,
                changes.ToArray(),
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

    private ModifyChange[] ProcessChanges(ModifyOperation operation, IDictionary changes, string paramName)
    {
        List<ModifyChange> attributes = new();

        foreach (DictionaryEntry kvp in changes)
        {
            string? attrName = kvp.Key.ToString() ?? "";
            if (string.IsNullOrWhiteSpace(attrName))
            {
                ErrorRecord error = new(
                    new ArgumentException($"-{paramName} key must not be empty/whitespace, skipping entry"),
                    $"Invalid{paramName}AttrKey",
                    ErrorCategory.InvalidOperation,
                    attrName);
                WriteError(error);
                continue;
            }

            if (Clear.Contains(attrName, _caseInsensitiveComparer))
            {
                continue;
            }

            WriteVerbose($"Using attribute for Set operation {operation} '{attrName}'");
            PartialAttribute attr = new(attrName, SchemaMetadata.ConvertToRawAttributeCollection(kvp.Value));
            attributes.Add(new(operation, attr));
        }

        return attributes.ToArray();
    }
}
