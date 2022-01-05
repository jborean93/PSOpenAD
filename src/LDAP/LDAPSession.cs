using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO.Pipelines;

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

        public int Bind(string dn, string password, LDAPControl[]? controls = null)
        {
            BindRequestSimple request = new BindRequestSimple(NextMessageId(), controls, Version, dn, password);
            PutRequest(request);

            return request.MessageId;
        }

        public int SaslBind(string dn, string mechanism, byte[] cred, LDAPControl[]? controls = null)
        {
            BindRequestSasl request = new BindRequestSasl(NextMessageId(), controls, Version, dn, mechanism, cred);
            PutRequest(request);

            return request.MessageId;
        }

        public int ExtendedRequest(string name, byte[]? value = null, LDAPControl[]? controls = null)
        {
            ExtendedRequest request = new ExtendedRequest(NextMessageId(), controls, name, value);
            PutRequest(request);

            return request.MessageId;
        }

        public int SearchRequest(string baseObject, SearchScope scope, DereferencingPolicy derefAliases,
            int sizeLimit, int timeLimit, bool typesOnly, LDAPFilter filter, string[] attributeSelection,
            LDAPControl[]? controls = null)
        {
            SearchRequest request = new SearchRequest(NextMessageId(), controls, baseObject, scope, derefAliases,
                sizeLimit, timeLimit, typesOnly, filter, attributeSelection);
            PutRequest(request);

            return request.MessageId;
        }

        public int Unbind()
        {
            UnbindRequest request = new UnbindRequest(NextMessageId(), null);
            PutRequest(request);

            return request.MessageId;
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
            {
                _incoming.Reader.AdvanceTo(readResult.Buffer.Start, readResult.Buffer.End);
                return null;
            }

            const AsnEncodingRules ruleSet = AsnEncodingRules.BER;
            AsnDecoder.ReadSequence(buffer, ruleSet, out var sequenceOffset, out var sequenceLength,
                out var consumed);
            try
            {
                return LDAPMessage.FromBytes(buffer.Slice(sequenceOffset, sequenceLength), out var _,
                    ruleSet: ruleSet);
            }
            finally
            {
                _incoming.Reader.AdvanceTo(readResult.Buffer.Slice(consumed).Start);
            }
        }

        private void PutRequest(LDAPMessage message)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.BER);
            using (AsnWriter.Scope _ = writer.PushSequence())
            {
                writer.WriteInteger(message.MessageId);
                message.ToBytes(writer);
            }

            _outgoing.Add(writer.Encode());
        }

        private int NextMessageId()
        {
            int messageId = _messageCounter + 1;
            _messageCounter++;

            return messageId;
        }
    }
}
