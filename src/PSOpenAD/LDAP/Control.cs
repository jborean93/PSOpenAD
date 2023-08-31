using System;
using System.Formats.Asn1;
using System.Text;

namespace PSOpenAD.LDAP;

/// <summary>LDAP Control information</summary>
/// <remarks>
/// <para>
/// The ASN.1 structure is defined as
/// </para>
/// <para>
///     Controls ::= SEQUENCE OF control Control
///
///     Control ::= SEQUENCE {
///          controlType             LDAPOID,
///          criticality             BOOLEAN DEFAULT FALSE,
///          controlValue            OCTET STRING OPTIONAL }
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11">4.1.11. Controls</see>
internal class LDAPControl
{
    /// <summary>The OID of the control this entry represents.</summary>
    public string ControlType { get; internal set; }

    /// <summary>Whether the control must be understood by the peer or not.</summary>
    public bool Criticality { get; internal set; }

    public LDAPControl(string controlType, bool criticality)
    {
        ControlType = controlType;
        Criticality = criticality;
    }

    public static LDAPControl FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        string controlType = Encoding.UTF8.GetString(AsnDecoder.ReadOctetString(data, ruleSet, out var consumed));
        data = data[bytesConsumed..];
        bytesConsumed += consumed;

        bool criticality = false;
        byte[]? value = null;
        while (data.Length > 0)
        {
            Asn1Tag tag = Asn1Tag.Decode(data, out var tagConsumed);
            if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.Boolean)
            {
                criticality = AsnDecoder.ReadBoolean(data, ruleSet, out consumed, expectedTag: tag);
                data = data[consumed..];
                bytesConsumed += consumed;
            }
            else if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.OctetString)
            {
                value = AsnDecoder.ReadOctetString(data, ruleSet, out consumed, expectedTag: tag);
                data = data[consumed..];
                bytesConsumed += consumed;
            }
            else
            {
                // In a peer is using a newer syntax with additional fields, just ignore them.
                AsnDecoder.ReadEncodedValue(data, ruleSet, out var _1, out var _2, out consumed);
                data = data[consumed..];
                bytesConsumed += consumed;
            }
        }

        return controlType switch
        {
            ShowDeleted.LDAP_SERVER_SHOW_DELETED_OID => new ShowDeleted(criticality),
            ShowDeactivatedLink.LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID => new ShowDeactivatedLink(criticality),
            PagedResultControl.LDAP_PAGED_RESULT_OID_STRING => new PagedResultControl(criticality, value, ruleSet),
            _ => new LDAPControl(controlType, criticality),
        };
    }

    public void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence();
        writer.WriteOctetString(Encoding.UTF8.GetBytes(ControlType));
        writer.WriteBoolean(Criticality);
        ValueToBytes(writer);
    }

    protected virtual void ValueToBytes(AsnWriter writer)
    {
        return;
    }
}

/// <summary>
/// Used with an LDAP search to specify that the search results include any deleted objects that match the search
/// filter.
/// </summary>
/// <see href="https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/ldap-server-show-deleted-oid">LDAP_SERVER_SHOW_DELETED_OID</see>
internal class ShowDeleted : LDAPControl
{
    public const string LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417";

    public ShowDeleted(bool criticality) : base(LDAP_SERVER_SHOW_DELETED_OID, criticality) { }
}

/// <summary>
/// Used with an LDAP search to specify that link attributes that refer to deleted-objects are visible to the search
/// operation.
/// </summary>
/// <see href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/059e33fc-c7af-451e-92a9-fcb33d828f0f">LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID</see>
internal class ShowDeactivatedLink : LDAPControl
{
    public const string LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID = "1.2.840.113556.1.4.2065";

    public ShowDeactivatedLink(bool criticality) : base(LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID, criticality) { }
}

/// <summary>LDAP Control informatfor Simple Paged Resulsts Manipulation</summary>
/// <remarks>
/// <para>
/// The ASN.1 structure is defined as
/// </para>
/// <para>
///     pagedResultsControl ::= SEQUENCE {
///             controlType     1.2.840.113556.1.4.319,
///             criticality     BOOLEAN DEFAULT FALSE,
///             controlValue    searchControlValue
///     }
///
///     realSearchControlValue ::= SEQUENCE {
///             size            INTEGER (0..maxInt),
///                                     -- requested page size from client
///                                     -- result set size estimate from server
///             cookie          OCTET STRING
///     }
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc2696#section-2">2. The Control</see>
internal class PagedResultControl : LDAPControl
{
    public const string LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319";

    public int Size { get; set; }

    public byte[]? Cookie { get; set; }

    public PagedResultControl(bool criticality, int size, byte[]? cookie)
        : base(LDAP_PAGED_RESULT_OID_STRING, criticality)
    {
        Size = size;
        Cookie = cookie;
    }

    internal PagedResultControl(bool criticality, ReadOnlySpan<byte> value, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
        : base(LDAP_PAGED_RESULT_OID_STRING, criticality)
    {
        AsnDecoder.ReadSequence(value, ruleSet, out var offset, out var _1, out var _2);
        value = value[offset..];

        Size = (int)AsnDecoder.ReadInteger(value, ruleSet, out offset);
        value = value[offset..];

        Cookie = AsnDecoder.ReadOctetString(value, ruleSet, out _1);
    }

    protected override void ValueToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushOctetString();
        using AsnWriter.Scope _2 = writer.PushSequence();

        writer.WriteInteger(Size);
        writer.WriteOctetString(Cookie);
    }
}
