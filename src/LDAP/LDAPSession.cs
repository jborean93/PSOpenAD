using System;
using System.Formats.Asn1;
using System.IO.Pipelines;

namespace PSOpenAD.LDAP
{
    internal class LDAPSession
    {
        private readonly Pipe _outgoing = new();

        private int _messageCounter;

        public int Version { get; }

        public PipeReader Outgoing => _outgoing.Reader;

        public LDAPSession(int version = 3)
        {
            Version = version;
        }

        public int Bind(string dn, string password, LDAPControl[]? controls = null)
        {
            BindRequestSimple request = new(NextMessageId(), controls, Version, dn, password);
            PutRequest(request);

            return request.MessageId;
        }

        public int SaslBind(string dn, string mechanism, byte[] cred, LDAPControl[]? controls = null)
        {
            BindRequestSasl request = new(NextMessageId(), controls, Version, dn, mechanism, cred);
            PutRequest(request);

            return request.MessageId;
        }

        public int ExtendedRequest(string name, byte[]? value = null, LDAPControl[]? controls = null)
        {
            ExtendedRequest request = new(NextMessageId(), controls, name, value);
            PutRequest(request);

            return request.MessageId;
        }

        public int SearchRequest(string baseObject, SearchScope scope, DereferencingPolicy derefAliases,
            int sizeLimit, int timeLimit, bool typesOnly, LDAPFilter filter, string[] attributeSelection,
            LDAPControl[]? controls = null)
        {
            SearchRequest request = new(NextMessageId(), controls, baseObject, scope, derefAliases,
                sizeLimit, timeLimit, typesOnly, filter, attributeSelection);
            PutRequest(request);

            return request.MessageId;
        }

        public int Unbind()
        {
            UnbindRequest request = new(NextMessageId(), null);
            PutRequest(request);

            return request.MessageId;
        }

        public LDAPMessage? ReceiveData(ReadOnlySpan<byte> data, out int bytesConsumed)
        {
            if (!Asn1Helper.HasEnoughData(data))
            {
                bytesConsumed = 0;
                return null;
            }

            const AsnEncodingRules ruleSet = AsnEncodingRules.BER;
            AsnDecoder.ReadSequence(data, ruleSet, out var sequenceOffset, out var sequenceLength,
                out bytesConsumed);

            return LDAPMessage.FromBytes(data.Slice(sequenceOffset, sequenceLength), out var _,
                ruleSet: ruleSet);
        }

        private void PutRequest(LDAPMessage message)
        {
            AsnWriter writer = new(AsnEncodingRules.BER);
            using (AsnWriter.Scope _ = writer.PushSequence())
            {
                writer.WriteInteger(message.MessageId);
                message.ToBytes(writer);
                // TODO: controls
            }

            Memory<byte> buffer = _outgoing.Writer.GetMemory(writer.GetEncodedLength());
            int written = writer.Encode(buffer.Span);
            _outgoing.Writer.Advance(written);

            if (message is UnbindRequest)
                _outgoing.Writer.Complete();

            _outgoing.Writer.FlushAsync().GetAwaiter().GetResult();
        }

        private int NextMessageId()
        {
            int messageId = _messageCounter + 1;
            _messageCounter++;

            return messageId;
        }
    }
}
