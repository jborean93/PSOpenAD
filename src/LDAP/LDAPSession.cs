using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.IO.Pipelines;
using System.Threading;

namespace PSOpenAD.LDAP;

public enum SessionState
{
    /// <summary>Connection has not been opened, bind still needs to be done.</summary>
    BeforeOpen,

    /// <summary>Bind request submitted and waiting for a response.</summary>
    Binding,

    /// <summary>Connection has been opened and is available for subsequent requests.</summary>
    Opened,

    /// <summary>Connection has been closed (unbound) and no further operations can be submitted.</summary>
    Closed,
}

internal class LDAPSession
{
    private readonly Pipe _outgoing = new();
    private readonly StreamWriter? _logWriter;
    private readonly SemaphoreSlim _logLock = new(1, 1);
    private SessionState _state = SessionState.BeforeOpen;

    private int _messageCounter;

    public int Version { get; }

    public PipeReader Outgoing => _outgoing.Reader;

    public SessionState State
    {
        get => _state;
        internal set
        {
            StateChanged?.Invoke(this, value);
            _state = value;
        }
    }

    public event EventHandler<SessionState>? StateChanged;

    public LDAPSession(int version = 3, StreamWriter? writer = null)
    {
        Version = version;
        _logWriter = writer;
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
                "Cannot perform a SearchRequest until the connection is opened");
        }

        SearchRequest request = new(NextMessageId(), controls, baseObject, scope, derefAliases,
            sizeLimit, timeLimit, typesOnly, filter, attributeSelection);
        PutRequest(request);

        return request.MessageId;
    }

    public int Unbind()
    {
        if (State != SessionState.Opened)
            throw new InvalidOperationException("Cannot perform an Unbind until the connection is opened");

        UnbindRequest request = new(NextMessageId(), null);
        PutRequest(request);
        Close();

        return request.MessageId;
    }

    public LDAPMessage? ReceiveData(ReadOnlySpan<byte> data, out int bytesConsumed)
    {
        bytesConsumed = 0;
        TraceMsg("RECV", data);

        try
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
        catch (Exception e)
        {
            int msgLength = bytesConsumed > 0 ? bytesConsumed : data.Length;
            string msg = $"Failed to unpack LDAP message: {e.Message}";
            throw new UnpackLDAPMessageException(msg, data[..msgLength].ToArray(), e);
        }
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
        TraceMsg("SEND", buffer.Span);
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

    private void TraceMsg(string direction, ReadOnlySpan<byte> data)
    {
        if (_logWriter is null)
        {
            return;
        }

        string b64Data = Convert.ToBase64String(data);
        _logLock.Wait();
        try
        {
            _logWriter.WriteLine($"{direction}: {b64Data}");
            _logWriter.Flush();
        }
        finally
        {
            _logLock.Release();
        }
    }
}
