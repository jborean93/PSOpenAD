using PSOpenAD.LDAP;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.New, "OpenADObject",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(OpenADObject))]
public class NewOpenADObject : OpenADSessionCmdletBase
{
    private StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

    #region New-OpenAD* Parameters

    [Parameter(
        Mandatory = true,
        Position = 0
    )]
    [ValidateNotNull]
    public string Name { get; set; } = "";

    [Parameter(
        Mandatory = true,
        Position = 1
    )]
    [ValidateNotNull]
    public string Type { get; set; } = "";

    [Parameter]
    public string? Description { get; set; }

    [Parameter]
    public string? DisplayName { get; set; }

    [Parameter]
    public string? Path { get; set; }

    [Parameter]
    public IDictionary? OtherAttributes { get; set; }

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    #endregion

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        string namePrefix = Type.Equals("organizationalUnit", StringComparison.OrdinalIgnoreCase) ? "OU" : "CN";
        string escapedName = DistinguishedName.EscapeAttributeValue(Name);
        string entry = $"{namePrefix}={escapedName},{Path ?? session.DefaultNamingContext}";
        List<PartialAttribute> attributes = new()
        {
            new("objectClass", SchemaMetadata.ConvertToRawAttributeCollection(Type)),
        };

        HashSet<string> requestedAttributes = new(_caseInsensitiveComparer);
        if (OtherAttributes != null)
        {
            foreach (DictionaryEntry kvp in OtherAttributes)
            {
                string key = kvp.Key.ToString() ?? "";

                if (string.IsNullOrWhiteSpace(key) || !requestedAttributes.Add(key))
                {
                    ErrorRecord error = new(
                        new ArgumentException($"OtherAttributes key '{key}' must not be empty/whitespace or declared multiple times"),
                        "InvalidOtherAttributesKey",
                        ErrorCategory.InvalidOperation,
                        key);
                    WriteError(error);
                    continue;
                }

                WriteVerbose($"Using attribute for Add operation '{key}'");
                attributes.Add(new(key, SchemaMetadata.ConvertToRawAttributeCollection(kvp.Value)));
            }
        }

        if (!string.IsNullOrWhiteSpace(Description) && requestedAttributes.Add("description"))
        {
            attributes.Add(new("description", SchemaMetadata.ConvertToRawAttributeCollection(Description)));
        }

        if (!string.IsNullOrWhiteSpace(DisplayName) && requestedAttributes.Add("displayName"))
        {
            attributes.Add(new("displayName", SchemaMetadata.ConvertToRawAttributeCollection(DisplayName)));
        }

        PartialAttribute[] attributesToCreate = attributes.ToArray();
        HashSet<string> searchProperties = OpenADObject.DEFAULT_PROPERTIES
            .Select(p => p.Item1)
            .ToHashSet(_caseInsensitiveComparer);
        searchProperties.UnionWith(attributesToCreate.Select(a => a.Name));

        SearchResultEntry? searchResult = null;
        if (ShouldProcess(entry, "Create"))
        {
            WriteVerbose($"Adding LDAP object '{entry}'");
            AddResponse resp = Operations.LdapAddRequest(
                session.Connection,
                entry,
                attributesToCreate,
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
                ).FirstOrDefault();

                if (searchResult == null)
                {
                    ErrorRecord error = new(
                        new InvalidOperationException($"Failed to find newly created object '{entry}' for -PassThru"),
                        "CannotFindNewObject",
                        ErrorCategory.NotSpecified,
                        entry);
                    WriteError(error);
                    return;
                }
            }
        }
        else if (PassThru)
        {
            // When using -WhatIf with -PassThru a dummy result is used to build the final object.
            PartialAttribute[] whatIfAttributes = attributesToCreate.Union(new[]
            {
                new PartialAttribute("distinguishedName", SchemaMetadata.ConvertToRawAttributeCollection(entry)),
                new PartialAttribute("name", SchemaMetadata.ConvertToRawAttributeCollection(Name)),
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
