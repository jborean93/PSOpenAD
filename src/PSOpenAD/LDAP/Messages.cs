using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
using System.Text;

namespace PSOpenAD.LDAP;

public enum DereferencingPolicy
{
    /// <summary>Do not dereference aliases in searching or in locating the base object of the search.</summary>
    Never,

    /// <summary>
    /// While searching subordinates of the base object, dereference any alaises within the search scope.
    /// </summary>
    InSearching,

    /// <summary>
    /// Dereference aliases in locating the base object of the search but not when searching subordinates of the
    /// base object.
    /// </summary>
    FindingBaseObj,

    /// <summary>Dereference aliases both in searching and in locating the base object of the search.</summary>
    Always,
}

public enum SearchScope
{
    /// <summary>Scope is constrained to the entry named by BaseObject.</summary>
    Base,

    /// <summary>Scope is constrained to the immediate subordinates of the entry named by BaseObject.</summary>
    OneLevel,

    /// <summary>Scope is constrained to the entry named by BaseObject and to all its subordinates.</summary>
    Subtree,
}

/// <summary>LDAP Message</summary>
/// <remarks>
/// <para>
/// This is the base class used by all LDAP messages exchanged between the client and server.
/// </para>
/// <para>
/// The ASN.1 structure is defined as
///     LDAPMessage ::= SEQUENCE {
///          messageID       MessageID,
///          protocolOp      CHOICE {
///               bindRequest           BindRequest,
///               bindResponse          BindResponse,
///               unbindRequest         UnbindRequest,
///               searchRequest         SearchRequest,
///               searchResEntry        SearchResultEntry,
///               searchResDone         SearchResultDone,
///               searchResRef          SearchResultReference,
///               modifyRequest         ModifyRequest,
///               modifyResponse        ModifyResponse,
///               addRequest            AddRequest,
///               addResponse           AddResponse,
///               delRequest            DelRequest,
///               delResponse           DelResponse,
///               modDNRequest          ModifyDNRequest,
///               modDNResponse         ModifyDNResponse,
///               compareRequest        CompareRequest,
///               compareResponse       CompareResponse,
///               abandonRequest        AbandonRequest,
///               extendedReq           ExtendedRequest,
///               extendedResp          ExtendedResponse,
///               ...,
///               intermediateResponse  IntermediateResponse },
///          controls       [0] Controls OPTIONAL }
///
///     MessageID ::= INTEGER (0 ..  maxInt)
///
///     maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1">4.1.1. Message Envelope</see>
internal abstract class LDAPMessage
{
    /// <summary>The value used to uniquely identify a message exchanged between the client and server.</summary>
    public int MessageId { get; internal set; }

    /// <summary>Optional set of controls to send to the peer.</summary>
    public LDAPControl[]? Controls { get; internal set; }

    internal LDAPMessage(int messageId, IEnumerable<LDAPControl>? controls)
    {
        MessageId = messageId;
        Controls = controls?.ToArray();
    }

    public virtual void ToBytes(AsnWriter writer) => throw new NotImplementedException();

    public static LDAPMessage FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        int messageId = (int)AsnDecoder.ReadInteger(data, ruleSet, out var consumed);
        data = data[consumed..];
        bytesConsumed += consumed;

        Asn1Tag protocolOpTag = Asn1Tag.Decode(data, out int protocolOpConsumed);
        if (protocolOpTag.TagClass != TagClass.Application)
            throw new InvalidDataException("Received unexpected LDAP payload");

        AsnDecoder.ReadSequence(data, ruleSet, out var protocolOpOffset, out var protocolOpLength,
            out consumed, protocolOpTag);
        ReadOnlySpan<byte> protocolOpBuffer = data.Slice(protocolOpOffset, protocolOpLength);
        data = data[consumed..];
        bytesConsumed += consumed;

        List<LDAPControl>? controls = null;
        string? responseName = null;
        while (data.Length > 0)
        {
            Asn1Tag nextTag = Asn1Tag.Decode(data, out var tagConsumed);
            if (nextTag.TagClass == TagClass.ContextSpecific && nextTag.TagValue == 0)
            {
                controls = new List<LDAPControl>();

                AsnDecoder.ReadSequence(data, ruleSet, out var controlOffset, out var controlLength, out consumed,
                    expectedTag: nextTag);

                ReadOnlySpan<byte> controlBuffer = data.Slice(controlOffset, controlLength);

                while (controlBuffer.Length > 0)
                {
                    AsnDecoder.ReadSequence(controlBuffer, ruleSet, out var offset, out var length,
                        out var controlConsumed);
                    LDAPControl control = LDAPControl.FromBytes(controlBuffer.Slice(offset, length), out var _,
                        ruleSet: ruleSet);
                    controls.Add(control);
                    controlBuffer = controlBuffer[controlConsumed..];
                }
            }
            else if (nextTag.TagClass == TagClass.ContextSpecific && nextTag.TagValue == 10)
            {
                // Defined in MS-ADTS - NoticeOfDisconnectionLDAPMessage. This is an extension of LDAPMessage in
                // the RFC but AD replies with this on critical failures where it has torn down the connection.
                byte[] responseNameBytes = AsnDecoder.ReadOctetString(data, ruleSet, out consumed,
                    expectedTag: nextTag);

                responseName = Encoding.UTF8.GetString(responseNameBytes);
            }
            else
            {
                // In a peer is using a newer syntax with additional fields, just ignore them.
                AsnDecoder.ReadEncodedValue(data, ruleSet, out var _1, out var _2, out consumed);
            }

            data = data[consumed..];
            bytesConsumed += consumed;
        }

        switch (protocolOpTag.TagValue)
        {
            case BindResponse.TAG_NUMBER:
                return BindResponse.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case SearchResultEntry.TAG_NUMBER:
                return SearchResultEntry.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case SearchResultDone.TAG_NUMBER:
                return SearchResultDone.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case ModifyResponse.TAG_NUMBER:
                return ModifyResponse.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case AddResponse.TAG_NUMBER:
                return AddResponse.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case DelResponse.TAG_NUMBER:
                return DelResponse.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case ModifyDNResponse.TAG_NUMBER:
                return ModifyDNResponse.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case SearchResultReference.TAG_NUMBER:
                return SearchResultReference.FromBytes(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                    ruleSet: ruleSet);

            case ExtendedResponse.TAG_NUMBER:
                ExtendedResponse resp = ExtendedResponse.FromBytes(messageId, controls?.ToArray(),
                    protocolOpBuffer, out var _, ruleSet: ruleSet);

                // If dealing with MS AD it may encode the ResponseName as part of the LDAPMessage rather than the
                // ExtendedResponse message. This just massages the data so they actually align with the protocol
                // docs.
                if (responseName != null && resp.Name == null)
                    resp.Name = responseName;

                return resp;

            default:
                throw new NotImplementedException(
                    $"Received unknown LDAP response with tag {protocolOpTag.TagValue}");
        }
    }
}

/// <summary>LDAP Bind Request</summary>
/// <remarks>
/// <para>
/// This is an abstract class and either BindRequestSimple or BindRequestSasl should be used.
/// <para/>
/// <para>
/// The ASN.1 structure is defined as
///
///     BindRequest ::= [APPLICATION 0] SEQUENCE {
///         version                 INTEGER (1 ..  127),
///         name                    LDAPDN,
///         authentication          AuthenticationChoice }
///
///     AuthenticationChoice ::= CHOICE {
///         simple                  [0] OCTET STRING,
///                                 -- 1 and 2 reserved
///         sasl                    [3] SaslCredentials,
///         ...  }
///
///     SaslCredentials ::= SEQUENCE {
///         mechanism               LDAPString,
///         credentials             OCTET STRING OPTIONAL }
/// </para>
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.2">4.2. Bind Operation</see>
internal abstract class BindRequest : LDAPMessage
{
    public const int TAG_NUMBER = 0;

    /// <summary>The LDAP protocol version number, this should be 3.</summary>
    public int Version { get; internal set; }

    /// <summary>
    /// The name of the directory object the client wishes to bind as, use an empty string for an anonymous user
    /// bind.
    /// </summary>
    public string Name { get; internal set; }

    internal BindRequest(int messageId, IEnumerable<LDAPControl>? controls, int version, string name)
        : base(messageId, controls)
    {
        Version = version;
        Name = name;
    }
}

/// <summary>LDAP Simple Bind Request</summary>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.2">4.2. Bind Operation</see>
internal class BindRequestSimple : BindRequest
{
    /// <summary>
    /// The password to authenticate with, use an empty string for an anonymous user bind.
    /// </summary>
    public string Password { get; internal set; }

    public BindRequestSimple(int messageId, IEnumerable<LDAPControl>? controls, int version, string name,
        string password) : base(messageId, controls, version, name)
    {
        Password = password;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _ = writer.PushSequence(new Asn1Tag(TagClass.Application, TAG_NUMBER,
            true));

        writer.WriteInteger(Version);
        writer.WriteOctetString(Encoding.UTF8.GetBytes(Name));

        Asn1Tag tag = new(TagClass.ContextSpecific, 0, false);
        writer.WriteOctetString(Encoding.UTF8.GetBytes(Password), tag);
    }
}

/// <summary>LDAP SASL Bind Request</summary>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.2">4.2. Bind Operation</see>
internal class BindRequestSasl : BindRequest
{
    /// <summary>The SASL mechanism identifier.</summary>
    public string Mechanism { get; internal set; }

    /// <summary>The SASL credential buffer to exchange.</summary>
    public byte[] Credentials { get; internal set; }

    public BindRequestSasl(int messageId, IEnumerable<LDAPControl>? controls, int version, string name,
        string mechanism, byte[] credentials) : base(messageId, controls, version, name)
    {
        Mechanism = mechanism;
        Credentials = credentials;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, TAG_NUMBER,
            true));

        writer.WriteInteger(Version);
        writer.WriteOctetString(Encoding.UTF8.GetBytes(Name));

        Asn1Tag tag = new(TagClass.ContextSpecific, 3, false);
        using AsnWriter.Scope _2 = writer.PushSequence(tag);
        writer.WriteOctetString(Encoding.UTF8.GetBytes(Mechanism));

        if (Credentials.Length > 0)
            writer.WriteOctetString(Credentials);
    }
}

/// <summary>LDAP Bind Response</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     BindResponse ::= [APPLICATION 1] SEQUENCE {
///         COMPONENTS OF LDAPResult,
///         serverSaslCreds    [7] OCTET STRING OPTIONAL }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.2.2">4.2.2. Bind Response</see>
internal class BindResponse : LDAPMessage
{
    public const int TAG_NUMBER = 1;

    /// <summary>The result of the bind operation including any error details.</summary>
    public LDAPResult Result { get; internal set; }

    /// <summary>Any credentials returned for the SASL mechanism.</summary>
    public byte[]? ServerSaslCreds { get; internal set; }

    public BindResponse(int messageId, IEnumerable<LDAPControl>? controls, LDAPResult result,
        byte[]? serverSaslCreds) : base(messageId, controls)
    {
        Result = result;
        ServerSaslCreds = serverSaslCreds;
    }

    public static BindResponse FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResult result = LDAPResult.FromBytes(data, out var consumed, ruleSet: ruleSet);
        data = data[consumed..];
        bytesConsumed += consumed;

        byte[]? saslCreds = null;
        while (data.Length > 0)
        {
            Asn1Tag tag = Asn1Tag.Decode(data, out var tagConsumed);
            if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 7)
            {
                saslCreds = AsnDecoder.ReadOctetString(data, ruleSet, out consumed, expectedTag: tag);
                data = data[consumed..];
            }
            else
            {
                // In a peer is using a newer syntax with additional fields, just ignore them.
                AsnDecoder.ReadEncodedValue(data, ruleSet, out var _1, out var _2, out consumed);
                data = data[consumed..];
            }

            bytesConsumed += consumed;
        }

        return new BindResponse(messageId, controls, result, saslCreds);
    }
}

/// <summary>LDAP Search Request</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     SearchRequest ::= [APPLICATION 3] SEQUENCE {
///          baseObject      LDAPDN,
///          scope           ENUMERATED {
///               baseObject              (0),
///               singleLevel             (1),
///               wholeSubtree            (2),
///               ...  },
///          derefAliases    ENUMERATED {
///               neverDerefAliases       (0),
///               derefInSearching        (1),
///               derefFindingBaseObj     (2),
///               derefAlways             (3) },
///          sizeLimit       INTEGER (0 ..  maxInt),
///          timeLimit       INTEGER (0 ..  maxInt),
///          typesOnly       BOOLEAN,
///          filter          Filter,
///          attributes      AttributeSelection }
///
///     AttributeSelection ::= SEQUENCE OF selector LDAPString
///                     -- The LDAPString is constrained to
///                     -- <attributeSelector> in Section 4.5.1.8
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1">4.5.1. Search Request</see>
internal class SearchRequest : LDAPMessage
{
    public const int TAG_NUMBER = 3;

    /// <summary>The name of the base object entry which the search is to be performed</summary>
    public string BaseObject { get; internal set; }

    /// <summary>The scope of the search to be performed.</summary>
    public SearchScope Scope { get; internal set; }

    /// <summary>Defines how alias entries are to be dereferenced during stages of the search operation.</summary>
    public DereferencingPolicy DerefAliases { get; internal set; }

    /// <summary>Maximum number of entries to be returned, 0 is no size restriction.</summary>
    public int SizeLimit { get; internal set; }

    /// <summary>Time limit (in seconds) allowed for a search, 0 is no time limit.</summary>
    public int TimeLimit { get; internal set; }

    /// <summary>Only return attribute names and not values when set to true.</summary>
    public bool TypesOnly { get; internal set; }

    /// <summary>The filter to apply to the search operation.</summary>
    public LDAPFilter Filter { get; internal set; }

    /// <summary>
    /// A list of attributes to be returned for each entry that matches the filter.
    /// Set to an empty array to return all user attributes.
    /// Set to <c>*</c> to return all user attributes in addition to the other listed attributes.
    /// Set to <c>1.1</c> to indicate no attributes should be returned.
    /// </summary>
    public string[] AttributeSelection { get; internal set; }

    public SearchRequest(int messageId, IEnumerable<LDAPControl>? controls, string baseObject, SearchScope scope,
        DereferencingPolicy derefAliases, int sizeLimit, int timeLimit, bool typesOnly, LDAPFilter filter,
        string[] attributeSelection) : base(messageId, controls)
    {
        BaseObject = baseObject;
        Scope = scope;
        DerefAliases = derefAliases;
        SizeLimit = sizeLimit;
        TimeLimit = timeLimit;
        TypesOnly = typesOnly;
        Filter = filter;
        AttributeSelection = attributeSelection;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, TAG_NUMBER,
            true));

        writer.WriteOctetString(Encoding.UTF8.GetBytes(BaseObject));
        writer.WriteEnumeratedValue(Scope);
        writer.WriteEnumeratedValue(DerefAliases);
        writer.WriteInteger(SizeLimit);
        writer.WriteInteger(TimeLimit);
        writer.WriteBoolean(TypesOnly);
        Filter.ToBytes(writer);

        using AsnWriter.Scope _2 = writer.PushSequence();
        foreach (string attr in AttributeSelection)
        {
            writer.WriteOctetString(Encoding.UTF8.GetBytes(attr));
        }
    }
}

/// <summary>LDAP Unbbind Request</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     UnbindRequest ::= [APPLICATION 2] NULL
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.3">4.3. Unbind Operation</see>
internal class UnbindRequest : LDAPMessage
{
    public const int TAG_NUMBER = 2;

    public UnbindRequest(int messageId, IEnumerable<LDAPControl>? controls) : base(messageId, controls) { }

    public override void ToBytes(AsnWriter writer)
    {
        writer.WriteNull(new Asn1Tag(TagClass.Application, TAG_NUMBER, false));
    }
}

/// <summary>LDAP Search Result Entry</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
///         objectName      LDAPDN,
///         attributes      PartialAttributeList }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2">4.5.2. Search Result</see>
internal class SearchResultEntry : LDAPMessage
{
    public const int TAG_NUMBER = 4;

    /// <summary>The object the result is for.</summary>
    public string ObjectName { get; internal set; }

    /// <summary>A list of attributes and their values for this object.</summary>
    public PartialAttribute[] Attributes { get; internal set; }

    public SearchResultEntry(int messageId, IEnumerable<LDAPControl>? controls, string objectName,
        PartialAttribute[] attributes) : base(messageId, controls)
    {
        ObjectName = objectName;
        Attributes = attributes;
    }

    public static SearchResultEntry FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        string objectName = Encoding.UTF8.GetString(AsnDecoder.ReadOctetString(data, ruleSet, out var consumed));
        data = data[consumed..];
        bytesConsumed += consumed;

        AsnDecoder.ReadSequence(data, ruleSet, out var attributeOffset, out var attributeLength, out consumed);
        bytesConsumed += consumed;

        List<PartialAttribute> attributes = new();
        ReadOnlySpan<byte> attributeSpan = data.Slice(attributeOffset, attributeLength);
        while (attributeSpan.Length > 0)
        {
            AsnDecoder.ReadSequence(attributeSpan, ruleSet, out attributeOffset, out attributeLength,
                out consumed);

            ReadOnlySpan<byte> attrEntrySpan = attributeSpan.Slice(attributeOffset, attributeLength);
            PartialAttribute attr = PartialAttribute.FromBytes(attrEntrySpan, out var _, ruleSet: ruleSet);
            attributes.Add(attr);

            attributeSpan = attributeSpan[consumed..];
        }

        return new SearchResultEntry(messageId, controls, objectName, attributes.ToArray());
    }
}

/// <summary>LDAP Search Result Done</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     SearchResultDone ::= [APPLICATION 5] LDAPResult
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2">4.5.2. Search Result</see>
internal class SearchResultDone : LDAPMessage
{
    public const int TAG_NUMBER = 5;

    /// <summary>The final result of a search operation.</summary>
    public LDAPResult Result { get; internal set; }

    public SearchResultDone(int messageId, IEnumerable<LDAPControl>? controls, LDAPResult result)
        : base(messageId, controls)
    {
        Result = result;
    }

    public static SearchResultDone FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResult result = LDAPResult.FromBytes(data, out var consumed, ruleSet: ruleSet);
        data = data[consumed..];
        bytesConsumed += consumed;

        return new SearchResultDone(messageId, controls, result);
    }
}

/// <summary>LDAP Modify Operation</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     ModifyRequest ::= [APPLICATION 6] SEQUENCE {
///          object          LDAPDN,
///          changes         SEQUENCE OF change SEQUENCE {
///               operation       ENUMERATED {
///                    add     (0),
///                    delete  (1),
///                    replace (2),
///                    ...  },
///               modification    PartialAttribute } }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.6">4.6. Modify Operation</see>
internal class ModifyRequest : LDAPMessage
{
    public const int TAG_NUMBER = 6;

    public string Entry { get; set; }

    public ModifyChange[] Changes { get; set; }

    public ModifyRequest(int messageId, IEnumerable<LDAPControl>? controls, string entry, ModifyChange[] changes)
        : base(messageId, controls)
    {
        Entry = entry;
        Changes = changes;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, TAG_NUMBER,
            true));

        writer.WriteOctetString(Encoding.UTF8.GetBytes(Entry));

        using AsnWriter.Scope _2 = writer.PushSequence();
        foreach (ModifyChange change in Changes)
        {
            change.ToBytes(writer);
        }
    }
}

/// <summary>LDAP Modify Response</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     ModifyResponse ::= [APPLICATION 7] LDAPResult
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.6">4.6. Modify Operation</see>
internal class ModifyResponse : LDAPMessage
{
    public const int TAG_NUMBER = 7;

    /// <summary>The final result of a search operation.</summary>
    public LDAPResult Result { get; internal set; }

    public ModifyResponse(int messageId, IEnumerable<LDAPControl>? controls, LDAPResult result)
        : base(messageId, controls)
    {
        Result = result;
    }

    public static ModifyResponse FromBytes(
        int messageId,
        IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data,
        out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResult result = LDAPResult.FromBytes(data, out var consumed, ruleSet: ruleSet);
        data = data[consumed..];
        bytesConsumed += consumed;

        return new ModifyResponse(messageId, controls, result);
    }
}

/// <summary>LDAP Add Operation</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     AddRequest ::= [APPLICATION 8] SEQUENCE {
///             entry           LDAPDN,
///             attributes      AttributeList }
///     AttributeList ::= SEQUENCE OF attribute Attribute
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.7">4.7. Add Operation</see>
internal class AddRequest : LDAPMessage
{
    public const int TAG_NUMBER = 8;

    public string Entry { get; set; }

    public PartialAttribute[] Attributes { get; set; } = Array.Empty<PartialAttribute>();

    public AddRequest(int messageId, IEnumerable<LDAPControl>? controls, string entry, PartialAttribute[] attributes)
        : base(messageId, controls)
    {
        Entry = entry;
        Attributes = attributes;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, TAG_NUMBER,
            true));

        writer.WriteOctetString(Encoding.UTF8.GetBytes(Entry));

        using AsnWriter.Scope _2 = writer.PushSequence();
        foreach (PartialAttribute attr in Attributes)
        {
            attr.ToBytes(writer);
        }
    }
}

/// <summary>LDAP Add Response</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     AddResponse ::= [APPLICATION 9] LDAPResult
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.7">4.7. Add Operation</see>
internal class AddResponse : LDAPMessage
{
    public const int TAG_NUMBER = 9;

    /// <summary>The final result of a search operation.</summary>
    public LDAPResult Result { get; internal set; }

    public AddResponse(int messageId, IEnumerable<LDAPControl>? controls, LDAPResult result)
        : base(messageId, controls)
    {
        Result = result;
    }

    public static AddResponse FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResult result = LDAPResult.FromBytes(data, out var consumed, ruleSet: ruleSet);
        data = data[consumed..];
        bytesConsumed += consumed;

        return new AddResponse(messageId, controls, result);
    }
}

/// <summary>LDAP Del Operation</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     DelRequest ::= [APPLICATION 10] LDAPDN
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.8">4.8. Delete Operation</see>
internal class DelRequest : LDAPMessage
{
    public const int TAG_NUMBER = 10;

    public string DistinguishedName { get; internal set; }

    public DelRequest(int messageId, IEnumerable<LDAPControl>? controls, string dn)
        : base(messageId, controls)
    {
        DistinguishedName = dn;
    }

    public override void ToBytes(AsnWriter writer)
    {
        writer.WriteOctetString(Encoding.UTF8.GetBytes(DistinguishedName),
            new Asn1Tag(TagClass.Application, TAG_NUMBER, false));
    }
}

/// <summary>LDAP Del Response</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     DelResponse ::= [APPLICATION 11] LDAPResult
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.8">4.8. Delete Operation</see>
internal class DelResponse : LDAPMessage
{
    public const int TAG_NUMBER = 11;

    /// <summary>The final result of a delete operation.</summary>
    public LDAPResult Result { get; internal set; }

    public DelResponse(int messageId, IEnumerable<LDAPControl>? controls, LDAPResult result)
        : base(messageId, controls)
    {
        Result = result;
    }

    public static DelResponse FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResult result = LDAPResult.FromBytes(data, out var consumed, ruleSet: ruleSet);
        data = data[consumed..];
        bytesConsumed += consumed;

        return new DelResponse(messageId, controls, result);
    }
}

/// <summary>LDAP Modify DN Operation</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
///             entry           LDAPDN,
///             newrdn          RelativeLDAPDN,
///             deleteoldrdn    BOOLEAN,
///             newSuperior     [0] LDAPDN OPTIONAL }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.9">4.9. Modify DNOperation</see>
internal class ModifyDNRequest : LDAPMessage
{
    public const int TAG_NUMBER = 12;

    public string Entry { get; set; }

    public string NewRDN { get; set; }

    public bool DeleteOldRDN { get; set; }

    public string? NewSuperior { get; set; }

    public ModifyDNRequest(
        int messageId,
        IEnumerable<LDAPControl>? controls,
        string entry,
        string newRDN,
        bool deleteOldRDN,
        string? newSuperior)
        : base(messageId, controls)
    {
        Entry = entry;
        NewRDN = newRDN;
        DeleteOldRDN = deleteOldRDN;
        NewSuperior = newSuperior;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, TAG_NUMBER,
            true));

        writer.WriteOctetString(Encoding.UTF8.GetBytes(Entry));
        writer.WriteOctetString(Encoding.UTF8.GetBytes(NewRDN));
        writer.WriteBoolean(DeleteOldRDN);
        if (!string.IsNullOrWhiteSpace(NewSuperior))
        {
            writer.WriteOctetString(
                Encoding.UTF8.GetBytes(NewSuperior),
                new Asn1Tag(TagClass.ContextSpecific, 0));
        }
    }
}

/// <summary>LDAP Modify DN Response</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     ModifyDNResponse ::= [APPLICATION 13] LDAPResult
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.9">4.9. Modify DN Operation</see>
internal class ModifyDNResponse : LDAPMessage
{
    public const int TAG_NUMBER = 13;

    /// <summary>The final result of a search operation.</summary>
    public LDAPResult Result { get; internal set; }

    public ModifyDNResponse(
        int messageId,
        IEnumerable<LDAPControl>? controls,
        LDAPResult result)
        : base(messageId, controls)
    {
        Result = result;
    }

    public static ModifyDNResponse FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResult result = LDAPResult.FromBytes(data, out var consumed, ruleSet: ruleSet);
        data = data[consumed..];
        bytesConsumed += consumed;

        return new ModifyDNResponse(messageId, controls, result);
    }
}

/// <summary>LDAP Search Result Reference</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     SearchResultReference ::= [APPLICATION 19] SEQUENCE
///                               SIZE (1..MAX) OF uri URI
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.2">4.5.2. Search Result</see>
internal class SearchResultReference : LDAPMessage
{
    public const int TAG_NUMBER = 19;

    /// <summary>References returned in the search result.</summary>
    public string[] Uris { get; internal set; }

    public SearchResultReference(int messageId, IEnumerable<LDAPControl>? controls, string[] uris)
        : base(messageId, controls)
    {
        Uris = uris;
    }

    public static SearchResultReference FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        List<string> uris = new();
        while (data.Length > 0)
        {
            byte[] rawUri = AsnDecoder.ReadOctetString(data, ruleSet, out var consumed);
            uris.Add(Encoding.UTF8.GetString(rawUri));

            data = data[consumed..];
            bytesConsumed += consumed;
        }

        return new SearchResultReference(messageId, controls, uris.ToArray());
    }
}

/// <summary>LDAP Extended Operation Request</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
///                  requestName      [0] LDAPOID,
///                  requestValue     [1] OCTET STRING OPTIONAL }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.12">4.12. Extended Operation</see>
internal class ExtendedRequest : LDAPMessage
{
    public const int TAG_NUMBER = 23;

    /// <summary>The extended request identifier OID.</summary>
    public string Name { get; internal set; }

    /// <summary>Data for the request, the structure is dependent on the request being performed.</summary>
    public byte[]? Value { get; internal set; }

    public ExtendedRequest(int messageId, IEnumerable<LDAPControl>? controls, string name, byte[]? value)
        : base(messageId, controls)
    {
        Name = name;
        Value = value;
    }

    public override void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, TAG_NUMBER,
            true));

        writer.WriteOctetString(Encoding.UTF8.GetBytes(Name), tag: new Asn1Tag(TagClass.ContextSpecific, 0));
        if (Value != null)
        {
            writer.WriteOctetString(Value, tag: new Asn1Tag(TagClass.ContextSpecific, 1));
        }
    }
}

/// <summary>LDAP Extended Operation Response</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
///                  COMPONENTS OF LDAPResult,
///                  responseName     [10] LDAPOID OPTIONAL,
///                  responseValue    [11] OCTET STRING OPTIONAL }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.12">4.12. Extended Operation</see>
internal class ExtendedResponse : LDAPMessage
{
    public const int TAG_NUMBER = 24;

    /// <summary>The result of the extended request.</summary>
    public LDAPResult Result { get; internal set; }

    /// <summary>The request name OID as returned by the server.</summary>
    public string? Name { get; internal set; }

    /// <summary>The response data for the extended operation.</summary>
    public byte[]? Value { get; internal set; }

    public ExtendedResponse(int messageId, IEnumerable<LDAPControl>? controls, LDAPResult result, string? name,
        byte[]? value) : base(messageId, controls)
    {
        Result = result;
        Name = name;
        Value = value;
    }

    public static ExtendedResponse FromBytes(int messageId, IEnumerable<LDAPControl>? controls,
        ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResult result = LDAPResult.FromBytes(data, out var consumed, ruleSet: ruleSet);
        data = data[consumed..];
        bytesConsumed += consumed;

        string? requestName = null;
        byte[]? requestValue = null;
        while (data.Length > 0)
        {
            Asn1Tag tag = Asn1Tag.Decode(data, out var tagConsumed);
            if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 10)
            {
                byte[] value = AsnDecoder.ReadOctetString(data, ruleSet, out consumed, expectedTag: tag);
                requestName = Encoding.UTF8.GetString(value);
            }
            else if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 11)
            {
                requestValue = AsnDecoder.ReadOctetString(data, ruleSet, out consumed, expectedTag: tag);
            }
            else
            {
                // If a peer is using a newer syntax with additional fields, just ignore them.
                AsnDecoder.ReadEncodedValue(data, ruleSet, out var _1, out var _2, out consumed);
            }

            data = data[consumed..];
            bytesConsumed += consumed;
        }

        return new ExtendedResponse(messageId, controls, result, requestName, requestValue);
    }
}

/// <summary>LDAP Result Message</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     LDAPResult ::= SEQUENCE {
///          resultCode         ENUMERATED {
///               ...  },
///          matchedDN          LDAPDN,
///          diagnosticMessage  LDAPString,
///          referral           [3] Referral OPTIONAL }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.9">4.1.9. Result Message</see>
internal class LDAPResult
{
    /// <summary>The result code of the operation.</summary>
    public LDAPResultCode ResultCode { get; internal set; }

    /// <summary>Certain failure codes may set the DN of object related to the failure.</summary>
    public string MatchedDN { get; internal set; }

    /// <summary>Further error details associated with the error.</summary>
    public string DiagnosticsMessage { get; internal set; }

    /// <summary>The referrals from the server that can be used to complete the operation.</summary>
    public string[]? Referrals { get; internal set; }

    public LDAPResult(LDAPResultCode resultCode, string matchedDN, string diagnosticsMessage,
        string[]? referrals)
    {
        ResultCode = resultCode;
        MatchedDN = matchedDN;
        DiagnosticsMessage = diagnosticsMessage;
        Referrals = referrals;
    }

    public static LDAPResult FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        LDAPResultCode resultCode = AsnDecoder.ReadEnumeratedValue<LDAPResultCode>(data, ruleSet,
            out var consumed);
        data = data[consumed..];
        bytesConsumed += consumed;

        string matchedDN = Encoding.UTF8.GetString(AsnDecoder.ReadOctetString(data, ruleSet, out consumed));
        data = data[consumed..];
        bytesConsumed += consumed;

        string diagnosticsMessage = Encoding.UTF8.GetString(AsnDecoder.ReadOctetString(data, ruleSet,
            out consumed));
        data = data[consumed..];
        bytesConsumed += consumed;

        List<string>? referrals = null;
        if (data.Length > 0)
        {
            Asn1Tag nextTag = Asn1Tag.Decode(data, out consumed);
            if (nextTag.TagClass == TagClass.ContextSpecific && nextTag.TagValue == 3)
            {
                AsnDecoder.ReadSequence(data, ruleSet, out var offset, out var length, out consumed,
                    expectedTag: nextTag);
                ReadOnlySpan<byte> referralsSpan = data.Slice(offset, length);
                bytesConsumed += consumed;

                referrals = new List<string>();
                while (referralsSpan.Length > 0)
                {
                    byte[] referralUri = AsnDecoder.ReadOctetString(referralsSpan, ruleSet, out consumed);
                    referrals.Add(Encoding.UTF8.GetString(referralUri));
                    referralsSpan = referralsSpan[consumed..];
                }
            }
        }

        return new LDAPResult(resultCode, matchedDN, diagnosticsMessage, referrals?.ToArray());
    }
}

/// <summary>LDAP Partial Attribute</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     PartialAttribute ::= SEQUENCE {
///          type       AttributeDescription,
///          vals       SET OF value AttributeValue }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.7">4.1.7. Attribute and PartialAttribute</see>
internal class PartialAttribute
{
    /// <summary>The name of the attribute.</summary>
    public string Name { get; internal set; }

    /// <summary>Collection of raw values for the attribute.</summary>
    public byte[][] Values { get; internal set; }

    public PartialAttribute(string name, byte[][] values)
    {
        Name = name;
        Values = values;
    }

    public static PartialAttribute FromBytes(ReadOnlySpan<byte> data, out int bytesConsumed,
        AsnEncodingRules ruleSet = AsnEncodingRules.BER)
    {
        bytesConsumed = 0;

        string name = Encoding.UTF8.GetString(AsnDecoder.ReadOctetString(data, ruleSet, out var consumed));
        data = data[consumed..];
        bytesConsumed += consumed;

        AsnDecoder.ReadSetOf(data, ruleSet, out var valuesOffset, out var valuesLength, out consumed);
        bytesConsumed += consumed;

        List<byte[]> values = new();
        ReadOnlySpan<byte> valueSpan = data.Slice(valuesOffset, valuesLength);
        while (valueSpan.Length > 0)
        {
            byte[] value = AsnDecoder.ReadOctetString(valueSpan, ruleSet, out consumed);
            values.Add(value);
            valueSpan = valueSpan[consumed..];
        }

        return new PartialAttribute(name, values.ToArray());
    }

    public void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence();

        writer.WriteOctetString(Encoding.UTF8.GetBytes(Name));

        using AsnWriter.Scope _2 = writer.PushSetOf();
        foreach (byte[] val in Values)
        {
            writer.WriteOctetString(val);
        }
    }
}

internal enum ModifyOperation
{
    Add = 0,
    Delete = 1,
    Replace = 2,
}

/// <summary>LDAP Modify Operation Change</summary>
/// <remarks>
/// The ASN.1 structure is defined as
///     change SEQUENCE {
///         operation       ENUMERATED {
///             add     (0),
///             delete  (1),
///             replace (2),
///             ...  },
///         modification    PartialAttribute } }
/// </remarks>
/// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.6">4.6. Modify Operation</see>
internal class ModifyChange
{
    public ModifyOperation Operation { get; set; }
    public PartialAttribute Modification { get; set; }

    public ModifyChange(ModifyOperation operation, PartialAttribute modification)
    {
        Operation = operation;
        Modification = modification;
    }

    public void ToBytes(AsnWriter writer)
    {
        using AsnWriter.Scope _1 = writer.PushSequence();

        writer.WriteEnumeratedValue(Operation);
        Modification.ToBytes(writer);
    }
}
