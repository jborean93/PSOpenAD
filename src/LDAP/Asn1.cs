using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Text;

namespace PSOpenAD.LDAP
{
    internal abstract class LDAPMessage
    {
        public int MessageId { get; internal set; }
        public LDAPControl[]? Controls { get; internal set; }

        internal LDAPMessage(int messageId, LDAPControl[]? controls)
        {
            MessageId = messageId;
            Controls = controls;
        }
    }

    internal class BindResponse : LDAPMessage
    {
        internal const int TAG_NUMBER = 1;

        public LDAPResult Result { get; internal set; }
        public byte[]? ServerSaslCreds { get; internal set; }

        internal BindResponse(int messageId, LDAPControl[]? controls, LDAPResult result, byte[]? serverSaslCreds)
            : base(messageId, controls)
        {
            Result = result;
            ServerSaslCreds = serverSaslCreds;
        }
    }

    internal class ExtendedResponse : LDAPMessage
    {
        internal const int TAG_NUMBER = 24;

        public LDAPResult Result { get; internal set; }
        public string Name { get; internal set; }
        public byte[]? Value { get; internal set; }

        internal ExtendedResponse(int messageId, LDAPControl[]? controls, LDAPResult result, string name,
            byte[]? value) : base(messageId, controls)
        {
            Result = result;
            Name = name;
            Value = value;
        }
    }

    internal class LDAPResult
    {
        public LDAPResultCode ResultCode { get; internal set; }
        public string MatchedDN { get; internal set; }
        public string DiagnosticsMessage { get; internal set; }
        public string[]? Referrals { get; internal set; }

        internal LDAPResult(LDAPResultCode resultCode, string matchedDN, string diagnosticsMessage,
            string[]? referrals)
        {
            ResultCode = resultCode;
            MatchedDN = matchedDN;
            DiagnosticsMessage = diagnosticsMessage;
            Referrals = referrals;
        }
    }

    /// <summary>LDAP Control information</summary>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.11">4.1.11. Controls</see>
    internal class LDAPControl
    {
        /// <summary>The OID of the control this entry represents.</summary>
        public string ControlType { get; internal set; }

        /// <summary>Whether the control must be understood by the peer or not.</summary>
        public bool Criticality { get; internal set; }

        /// <summary>The raw control value if one is defined.</summary>
        public byte[]? Value { get; internal set; }

        internal LDAPControl(string controlType, bool criticality, byte[]? value)
        {
            ControlType = controlType;
            Criticality = criticality;
            Value = value;
        }
    }

    internal static class LDAPWriter
    {
        public static ReadOnlyMemory<byte> WriteLDAPFilter(string filter,
            AsnEncodingRules ruleSet = AsnEncodingRules.BER)
        {
            if (!(filter.StartsWith("(") && filter.EndsWith(")")))
                throw new ArgumentException();

            ReadOnlySpan<char> filterSpan = filter.AsSpan().Slice(1, filter.Length - 2);
            AsnWriter writer = new AsnWriter(ruleSet);

            if (filterSpan[0] == '&' || filterSpan[0] == '|') // and | or
            {
                filterSpan = filterSpan.Slice(1);
                if (!(filterSpan.StartsWith("(") && filterSpan.EndsWith(")")))
                    throw new ArgumentException();

                int tagValue = filterSpan[0] == '&' ? 0 : 1;
                using (AsnWriter.Scope _ = writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, tagValue, true)))
                {
                    while (filterSpan[0] == '(')
                    {
                        int endIdx = filterSpan.IndexOf(')');
                        ReadOnlyMemory<byte> entryValue = WriteLDAPFilter(filterSpan.Slice(0, endIdx).ToString());
                        writer.WriteEncodedValue(entryValue.Span);
                        filterSpan = filterSpan.Slice(1, endIdx - 2);
                    }
                }
            }
            else if (filterSpan[0] == '!') // not
            {
                ReadOnlyMemory<byte> subValue = WriteLDAPFilter(filterSpan.Slice(1).ToString());
                writer.WriteOctetString(subValue.Span, new Asn1Tag(TagClass.ContextSpecific, 2, false));
            }
            else // other
            {
                // AttributeValueAssertion
                //  equalityMatch   (3) - (attr=value)
                //  greaterOrEqual  (5) - (attr>=value)
                //  lessOrEqual     (6) - (attr<=value)
                //  approxMatch     (8) - (attr~=value)

                // SubstringFilter
                //  substrings      (4) - (attr=*) - multiple *'s can be used

                // AttributeDescription
                //  present         (7) - (attr)

                // MatchingRuleAssertion
                //  extensibleMatch (9) - () - this is weird and complex
            }

            return writer.Encode();
        }
    }

    internal static class LDAPReader
    {
        public static LDAPControl ReadLDAPControl(ReadOnlySpan<byte> data, out int bytesConsumed,
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

            return new LDAPControl(controlType, criticality, value);
        }

        public static LDAPMessage ReadLDAPMessage(ReadOnlySpan<byte> data, out int bytesConsumed,
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
            while (data.Length > 0)
            {
                Asn1Tag nextTag = Asn1Tag.Decode(data, out var tagConsumed);
                if (nextTag.TagClass == TagClass.ContextSpecific && nextTag.TagValue == 0)
                {
                    controls = new List<LDAPControl>();

                    AsnDecoder.ReadSequence(data, ruleSet, out var controlOffset, out var controlLength, out consumed,
                        expectedTag: nextTag);

                    ReadOnlySpan<byte> controlBuffer = data.Slice(controlOffset, controlOffset);
                    data = data[consumed..];

                    while (controlBuffer.Length > 0)
                    {
                        AsnDecoder.ReadSequence(controlBuffer, ruleSet, out var offset, out var length,
                            out var controlConsumed);
                        controls.Add(ReadLDAPControl(controlBuffer.Slice(offset, length), out var _,
                            ruleSet: ruleSet));
                        controlBuffer = controlBuffer[controlConsumed..];
                    }
                }
                else
                {
                    // In a peer is using a newer syntax with additional fields, just ignore them.
                    AsnDecoder.ReadEncodedValue(data, ruleSet, out var _1, out var _2, out consumed);
                    data = data[consumed..];
                }

                bytesConsumed += consumed;
            }

            switch (protocolOpTag.TagValue)
            {
                case BindResponse.TAG_NUMBER:
                    return ReadBindResponse(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                        ruleSet: ruleSet);

                case ExtendedResponse.TAG_NUMBER:
                    return ReadExtendedResponse(messageId, controls?.ToArray(), protocolOpBuffer, out var _,
                        ruleSet: ruleSet);

                default:
                    throw new NotImplementedException(protocolOpTag.TagValue.ToString());
            }
        }

        public static BindResponse ReadBindResponse(int messageId, LDAPControl[]? controls, ReadOnlySpan<byte> data,
            out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
        {
            bytesConsumed = 0;

            LDAPResult result = ReadLDAPResult(data, out var consumed, ruleSet: ruleSet);
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

        public static ExtendedResponse ReadExtendedResponse(int messageId, LDAPControl[]? controls,
            ReadOnlySpan<byte> data, out int bytesConsumed, AsnEncodingRules ruleSet = AsnEncodingRules.BER)
        {
            bytesConsumed = 0;

            LDAPResult result = ReadLDAPResult(data, out var consumed, ruleSet: ruleSet);
            data = data[consumed..];
            bytesConsumed += consumed;

            // While this field is mandatory in the spec I've seen it omitted from AD when sending a malformed wrapped
            // package in it's response.
            byte[] requestName;
            if (data.Length > 0)
            {
                requestName = AsnDecoder.ReadOctetString(data, ruleSet, out consumed,
                    expectedTag: new Asn1Tag(TagClass.ContextSpecific, 10));
                data = data[consumed..];
                bytesConsumed += consumed;
            }
            else
            {
                requestName = Array.Empty<byte>();
            }

            byte[]? requestValue = null;
            if (data.Length > 0)
            {
                requestValue = AsnDecoder.ReadOctetString(data, ruleSet, out consumed,
                    expectedTag: new Asn1Tag(TagClass.ContextSpecific, 11));
                data = data[consumed..];
                bytesConsumed += consumed;
            }

            return new ExtendedResponse(messageId, controls, result, Encoding.UTF8.GetString(requestName),
                requestValue);
        }

        public static LDAPResult ReadLDAPResult(ReadOnlySpan<byte> data, out int bytesConsumed,
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
}
