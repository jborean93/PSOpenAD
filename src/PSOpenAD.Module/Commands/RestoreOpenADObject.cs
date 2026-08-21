using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using System.Text;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsData.Restore, "OpenADObject",
    DefaultParameterSetName = DefaultSessionParameterSet,
    SupportsShouldProcess = true
)]
[OutputType(typeof(OpenADObject))]
public class RestoreOpenADObject : OpenADSessionCmdletBase
{
    private StringComparer _caseInsensitiveComparer = StringComparer.OrdinalIgnoreCase;

    private const string LAST_KNOWN_RDN = "msDS-LastKnownRDN";
    private const string LAST_KNOWN_PARENT = "lastKnownParent";
    private const string IS_DELETED = "isDeleted";
    private const string IS_RECYCLED = "isRecycled";
    private const string DISTINGUISHED_NAME = "distinguishedName";

    #region Restore-OpenADObject Parameters

    /// <summary>
    /// The distinguished name of the deleted object, as found with
    /// <c>Get-OpenADObject -IncludeDeletedObjects</c>. This is the mangled
    /// name inside the Deleted Objects container, not the original one.
    /// </summary>
    [Parameter(
        Mandatory = true,
        Position = 0,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true
    )]
    public ADObjectIdentity? Identity { get; set; }

    /// <summary>
    /// Restore to this container instead of the one the object was deleted
    /// from. Use when the original parent has itself been deleted, which
    /// otherwise fails with "the object's parent is deleted".
    /// </summary>
    [Parameter]
    public string? TargetPath { get; set; }

    /// <summary>
    /// Restore under this name instead of the one recorded in
    /// msDS-LastKnownRDN. Use when an object of that name has been recreated
    /// since the deletion.
    /// </summary>
    [Parameter]
    public string? NewName { get; set; }

    [Parameter]
    public SwitchParameter PassThru { get; set; }

    #endregion

    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        ArgumentNullException.ThrowIfNull(Identity);

        // Every request here needs LDAP_SERVER_SHOW_DELETED_OID. A deleted
        // object is invisible without it, so both the lookup and the modify
        // would otherwise fail with "no such object".
        List<LDAPControl> controls = new() { new ShowDeleted(true) };

        string? entry = Identity.DistinguishedName;
        if (entry == null)
        {
            WriteError(new ErrorRecord(
                new ArgumentException(
                    "Restore-OpenADObject requires the distinguished name of the deleted object, " +
                    "as returned by Get-OpenADObject -IncludeDeletedObjects."),
                "RestoreOpenADObjectIdentityNotDN",
                ErrorCategory.InvalidArgument,
                Identity));
            return;
        }

        SearchResultEntry? deleted = Operations.LdapSearchRequest(
            session.Connection,
            entry,
            SearchScope.Base,
            0,
            session.OperationTimeout,
            new FilterPresent("objectClass"),
            new[] { LAST_KNOWN_RDN, LAST_KNOWN_PARENT, IS_DELETED, IS_RECYCLED },
            controls,
            CancelToken,
            this,
            false,
            // Reported below as not found, rather than as a second, raw error.
            (r) => r.ResultCode == LDAPResultCode.NoSuchObject
        ).FirstOrDefault();

        if (deleted == null)
        {
            WriteError(new ErrorRecord(
                new ItemNotFoundException($"Cannot find a deleted object with the identity '{entry}'"),
                "RestoreOpenADObjectNotFound",
                ErrorCategory.ObjectNotFound,
                entry));
            return;
        }

        // A recycled object is not necessarily unrecoverable. Without the
        // Recycle Bin every deleted object is a recycled tombstone and the
        // directory still accepts the restore, with the attributes a tombstone
        // keeps. With the Recycle Bin enabled it refuses, so this is only used
        // to explain that failure.
        bool isRecycled = string.Equals(GetFirstValue(deleted, IS_RECYCLED), "TRUE",
            StringComparison.OrdinalIgnoreCase);

        // Keep the RDN attribute the object was deleted with - CN for most
        // things, OU for an organizational unit - rather than assuming CN.
        DistinguishedName parsed = DistinguishedName.Parse(entry);
        AttributeTypeAndValue? deletedRdn = parsed.RelativeNames.Length > 0
            ? parsed.RelativeNames[0].Values[0]
            : null;
        string rdnAttribute = deletedRdn?.Type ?? "CN";

        string? rdnValue = NewName ?? GetFirstValue(deleted, LAST_KNOWN_RDN) ?? GetNameFromDeletedRdn(deletedRdn);
        if (string.IsNullOrEmpty(rdnValue))
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException(
                    $"'{entry}' has no {LAST_KNOWN_RDN} to restore it under; supply -NewName."),
                "RestoreOpenADObjectNoRDN",
                ErrorCategory.InvalidOperation,
                entry));
            return;
        }

        string? parent = TargetPath ?? GetFirstValue(deleted, LAST_KNOWN_PARENT);
        if (string.IsNullOrEmpty(parent))
        {
            WriteError(new ErrorRecord(
                new InvalidOperationException(
                    $"'{entry}' has no {LAST_KNOWN_PARENT} to restore it into; supply -TargetPath."),
                "RestoreOpenADObjectNoParent",
                ErrorCategory.InvalidOperation,
                entry));
            return;
        }

        string newDN = $"{rdnAttribute}={DistinguishedName.EscapeAttributeValue(rdnValue)},{parent}";

        WriteVerbose($"Restoring '{entry}' -> '{newDN}'");
        if (!ShouldProcess($"'{entry}' -> '{newDN}'", "Restore"))
        {
            return;
        }

        // The restore is one modify carrying both changes. Splitting it into
        // two requests does not work: removing isDeleted on its own leaves the
        // object in the Deleted Objects container in an invalid state.
        ModifyChange[] changes = new[]
        {
            new ModifyChange(
                ModifyOperation.Delete,
                new PartialAttribute(IS_DELETED, Array.Empty<byte[]>())),
            new ModifyChange(
                ModifyOperation.Replace,
                new PartialAttribute(DISTINGUISHED_NAME, new[] { Encoding.UTF8.GetBytes(newDN) })),
        };

        WriteVerbose($"Starting LDAP modify request for '{entry}'");
        ModifyResponse resp = Operations.LdapModifyRequest(
            session.Connection,
            entry,
            changes,
            controls,
            CancelToken,
            null);
        if (resp.Result.ResultCode != LDAPResultCode.Success)
        {
            string msg = isRecycled
                ? $"Failed to restore '{entry}', which has been recycled. With the Recycle Bin enabled a " +
                    "recycled object cannot be restored and must be recovered from a backup"
                : $"Failed to restore '{entry}'";
            WriteError(new ErrorRecord(
                new LDAPException(msg, resp.Result),
                "RestoreOpenADObjectFailure",
                ErrorCategory.InvalidOperation,
                entry));
            return;
        }

        if (!PassThru)
        {
            return;
        }

        HashSet<string> searchProperties = OpenADObject.DEFAULT_PROPERTIES
            .Select(p => p.Item1)
            .ToHashSet(_caseInsensitiveComparer);

        WriteVerbose($"Getting PassThru result for '{newDN}'");
        SearchResultEntry? restored = Operations.LdapSearchRequest(
            session.Connection,
            newDN,
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

        if (restored != null)
        {
            WriteObject(GetOpenADObject.CreateOutputObject(
                session,
                restored,
                searchProperties,
                null,
                this));
        }
    }

    private static string? GetFirstValue(SearchResultEntry entry, string name)
    {
        PartialAttribute? attr = entry.Attributes
            .FirstOrDefault(a => string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase));
        if (attr == null || attr.Values.Length == 0)
        {
            return null;
        }
        return Encoding.UTF8.GetString(attr.Values[0]);
    }

    /// <summary>
    /// Gets the original name from the RDN of a deleted object, which the
    /// directory renames to "name\0ADEL:guid" (MS-ADTS 3.1.1.5.5.1.2). A
    /// tombstone keeps no msDS-LastKnownRDN, so this is where its name is kept.
    /// </summary>
    private static string? GetNameFromDeletedRdn(AttributeTypeAndValue? rdn)
    {
        if (rdn == null)
        {
            return null;
        }

        int idx = rdn.Value.LastIndexOf("\nDEL:", StringComparison.Ordinal);
        return idx > 0 ? rdn.Value[..idx] : null;
    }
}
