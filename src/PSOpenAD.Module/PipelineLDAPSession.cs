using PSOpenAD.LDAP;
using System;
using System.Formats.Asn1;
using System.IO;
using System.IO.Pipelines;
using System.Threading.Tasks;

namespace PSOpenAD.Module;

internal class PipelineLDAPSession : LDAPSession
{
    private readonly Pipe _outgoing = new();

    public PipeReader Outgoing => _outgoing.Reader;

    public PipelineLDAPSession(int version = 3, StreamWriter? writer = null) : base(version, writer)
    {}

    public override void CloseConnection()
    {
        _outgoing.Writer.Complete();
        Flush();
    }

    public override void WriteData(AsnWriter writer)
    {
        Memory<byte> buffer = _outgoing.Writer.GetMemory(writer.GetEncodedLength());

        // The buffer is rented and only holds the request once Encode has run, so
        // it is traced afterwards, and only as far as what was written.
        int written = writer.Encode(buffer.Span);
        TraceMsg("SEND", buffer.Span[..written]);
        _outgoing.Writer.Advance(written);
        Flush();
    }

    /// <summary>
    /// Waits for the flush to finish. A request past the pipe's pause threshold
    /// leaves the flush pending until the sender drains it, and calling
    /// GetResult() on a ValueTask that has not completed throws rather than
    /// waiting, so the pending case is handed to a Task first.
    /// </summary>
    private void Flush()
    {
        ValueTask<FlushResult> flush = _outgoing.Writer.FlushAsync();
        if (flush.IsCompleted)
        {
            flush.GetAwaiter().GetResult();
        }
        else
        {
            flush.AsTask().GetAwaiter().GetResult();
        }
    }
}
