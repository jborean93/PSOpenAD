using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO.Pipelines;

namespace PSOpenAD.LDAP;

public enum SessionState
{
    /// <summary>Connection has not been opened, bind still needs to be done.</summary>
    BeforeOpen,

    /// <summary>Bind request submitted and waiting for a response.</summary>
    Binding,

    /// <summary>Connection has been opened and is available for subsequent requests.</summary>
    Opened,

    /// <summary>Connection has been closed (unbound) and not further operations can be submitted.</summary>
    Closed,
}

internal class LDAPSession
{
    private readonly Pipe _outgoing = new();

    private int _messageCounter;

    public int Version { get; }

    public PipeReader Outgoing => _outgoing.Reader;

    public SessionState State { get; internal set; } = SessionState.BeforeOpen;

    public LDAPSession(int version = 3)
    {
        Version = version;
    }

    public void Close()
    {
        if (State != SessionState.Closed)
        {
            State = SessionState.Closed;
            _outgoing.Writer.Complete();
            _outgoing.Writer.FlushAsync().GetAwaiter().GetResult();
        }
    }

    public int Bind(string dn, string password, IEnumerable<LDAPControl>? controls = null)
    {
        if (State != SessionState.BeforeOpen)
        {
            throw new InvalidOperationException(
                "Cannot bind LDAP session on a connection that has already been opened");
        }

        State = SessionState.Binding;
        BindRequestSimple request = new(NextMessageId(), controls, Version, dn, password);
        PutRequest(request);

        return request.MessageId;
    }

    public int SaslBind(string dn, string mechanism, byte[] cred, IEnumerable<LDAPControl>? controls = null)
    {
        if (State != SessionState.BeforeOpen && State != SessionState.Binding)
        {
            throw new InvalidOperationException(
                "Cannot bind LDAP session on a connection that has already been opened");
        }

        State = SessionState.Binding;
        BindRequestSasl request = new(NextMessageId(), controls, Version, dn, mechanism, cred);
        PutRequest(request);

        return request.MessageId;
    }

    public int ExtendedRequest(string name, byte[]? value = null, IEnumerable<LDAPControl>? controls = null)
    {
        if (State == SessionState.Closed)
        {
            throw new InvalidOperationException(
                "Cannot perform an ExtendedRequest on a closed connection");
        }

        ExtendedRequest request = new(NextMessageId(), controls, name, value);
        PutRequest(request);

        return request.MessageId;
    }

    public int SearchRequest(string baseObject, SearchScope scope, DereferencingPolicy derefAliases, int sizeLimit,
        int timeLimit, bool typesOnly, LDAPFilter filter, string[] attributeSelection,
        IEnumerable<LDAPControl>? controls = null)
    {
        if (State != SessionState.Opened)
        {
            throw new InvalidOperationException(
                "Cannot perform a SearchRequest until the connection is openned");
        }

        SearchRequest request = new(NextMessageId(), controls, baseObject, scope, derefAliases,
            sizeLimit, timeLimit, typesOnly, filter, attributeSelection);
        PutRequest(request);

        return request.MessageId;
    }

    public int Unbind()
    {
        if (State != SessionState.Opened)
            throw new InvalidOperationException("Cannot perform an Unbind until the connection is openned");

        UnbindRequest request = new(NextMessageId(), null);
        PutRequest(request);
        Close();

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

        LDAPMessage? msg = LDAPMessage.FromBytes(data.Slice(sequenceOffset, sequenceLength), out var _,
            ruleSet: ruleSet);

        if (msg is BindResponse bindResp && bindResp.Result.ResultCode == LDAPResultCode.Success)
            State = SessionState.Opened;

        return msg;
    }

    private void PutRequest(LDAPMessage message)
    {
        AsnWriter writer = new(AsnEncodingRules.BER);
        using (AsnWriter.Scope _1 = writer.PushSequence())
        {
            writer.WriteInteger(message.MessageId);
            message.ToBytes(writer);

            if (message.Controls != null)
            {
                using AsnWriter.Scope _2 = writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, false));
                foreach (LDAPControl control in message.Controls)
                    control.ToBytes(writer);
            }
        }

        Memory<byte> buffer = _outgoing.Writer.GetMemory(writer.GetEncodedLength());
        int written = writer.Encode(buffer.Span);
        _outgoing.Writer.Advance(written);

        _outgoing.Writer.FlushAsync().GetAwaiter().GetResult();
    }

    private int NextMessageId()
    {
        int messageId = _messageCounter + 1;
        _messageCounter++;

        return messageId;
    }
}
