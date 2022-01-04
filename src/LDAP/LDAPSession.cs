using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO.Pipelines;
using System.Text;

namespace PSOpenAD.LDAP
{
    internal class LDAPSession
    {
        private readonly List<byte[]> _outgoing = new List<byte[]>();
        private readonly Pipe _incoming = new Pipe();

        private int _messageCounter = 0;

        public int Version { get; }

        public PipeWriter Incoming { get => _incoming.Writer; }

        public LDAPSession(int version = 3)
        {
            Version = version;
        }

        public int ExtendedRequest(string oid, byte[]? value = null)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            using (AsnWriter.Scope _ = writer.PushSequence(new Asn1Tag(TagClass.Application, 23, true)))
            {
                writer.WriteOctetString(Encoding.UTF8.GetBytes(oid), tag: new Asn1Tag(TagClass.ContextSpecific, 0));
                if (value != null)
                {
                    writer.WriteOctetString(value, tag: new Asn1Tag(TagClass.ContextSpecific, 1));
                }
            }

            return PutRequest(writer.Encode());
        }

        public int Bind(string dn, string password)
        {
            return BindRequest(dn, password: password);
        }

        public int SaslBind(string dn, string mechanism, ReadOnlySpan<byte> cred)
        {
            return BindRequest(dn, saslMech: mechanism, saslCred: cred);
        }

        public int SearchRequest(string baseObject, SearchScope scope, DereferencingPolicy derefPolicy, int sizeLimit,
            int timeLimit, bool typesOnly, string filter, List<string> attributeSelection)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            using (AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, 3, true)))
            {
                writer.WriteOctetString(Encoding.UTF8.GetBytes(baseObject));
                writer.WriteEnumeratedValue(scope);
                writer.WriteEnumeratedValue(derefPolicy);
                writer.WriteInteger(sizeLimit);
                writer.WriteInteger(timeLimit);
                writer.WriteBoolean(typesOnly);
                writer.WriteOctetString(LDAPWriter.WriteLDAPFilter(filter).Span,
                    new Asn1Tag(TagClass.Application, 7, false));
                using (AsnWriter.Scope _2 = writer.PushSequence())
                {
                    foreach (string attr in attributeSelection)
                    {
                        writer.WriteOctetString(Encoding.UTF8.GetBytes(attr));

                    }
                }
            }

            return PutRequest(writer.Encode());
        }

        public int Unbind()
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            writer.WriteNull(new Asn1Tag(TagClass.Application, 2, false));

            return PutRequest(writer.Encode());
        }

        public byte[] DataToSend()
        {
            if (_outgoing.Count > 0)
            {
                byte[] data = _outgoing[0];
                _outgoing.RemoveAt(0);
                return data;
            }

            throw new InvalidOperationException("No data available to send");
        }

        public LDAPMessage? NextEvent()
        {
            if (!_incoming.Reader.TryRead(out var readResult))
                return null;

            ReadOnlySpan<byte> buffer;
            if (readResult.Buffer.IsSingleSegment)
            {
                buffer = readResult.Buffer.FirstSpan;
            }
            else
            {
                // This is most likely very inefficient but not sure how to do this properly.
                buffer = readResult.Buffer.ToArray().AsSpan();
            }

            if (!Asn1Helper.HasEnoughData(buffer))
                return null;

            const AsnEncodingRules ruleSet = AsnEncodingRules.BER;
            AsnDecoder.ReadSequence(buffer, ruleSet, out var sequenceOffset, out var sequenceLength,
                out var consumed);
            try
            {
                return LDAPReader.ReadLDAPMessage(buffer.Slice(sequenceOffset, sequenceLength), out var _,
                    ruleSet: ruleSet);
            }
            finally
            {
                _incoming.Reader.AdvanceTo(readResult.Buffer.Slice(consumed).Start, readResult.Buffer.End);
            }
        }

        private int PutRequest(ReadOnlySpan<byte> data)
        {
            int messageId = _messageCounter += 1;
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            using (AsnWriter.Scope _ = writer.PushSequence())
            {
                writer.WriteInteger(messageId);
                writer.WriteEncodedValue(data);
            }

            _outgoing.Add(writer.Encode());

            return messageId;
        }

        private int BindRequest(string dn, string? password = null, string? saslMech = null,
            ReadOnlySpan<byte> saslCred = default)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            using (AsnWriter.Scope _1 = writer.PushSequence(new Asn1Tag(TagClass.Application, 0, true)))
            {
                writer.WriteInteger(3);
                writer.WriteOctetString(Encoding.UTF8.GetBytes(dn));

                if (String.IsNullOrEmpty(saslMech))
                {
                    Asn1Tag tag = new Asn1Tag(TagClass.ContextSpecific, 0, false);
                    writer.WriteOctetString(Encoding.UTF8.GetBytes(password ?? ""), tag);
                }
                else
                {
                    Asn1Tag tag = new Asn1Tag(TagClass.ContextSpecific, 3, false);
                    using AsnWriter.Scope _2 = writer.PushSequence(tag);
                    writer.WriteOctetString(Encoding.UTF8.GetBytes(saslMech ?? ""));

                    if (saslCred.Length > 0)
                        writer.WriteOctetString(saslCred);
                }
            }

            return PutRequest(writer.Encode());
        }
    }
}
