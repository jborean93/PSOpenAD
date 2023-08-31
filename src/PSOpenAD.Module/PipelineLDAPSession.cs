using PSOpenAD.LDAP;
using System;
using System.Formats.Asn1;
using System.IO;
using System.IO.Pipelines;

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
        _outgoing.Writer.FlushAsync().GetAwaiter().GetResult();
    }

    public override void WriteData(AsnWriter writer)
    {
        Memory<byte> buffer = _outgoing.Writer.GetMemory(writer.GetEncodedLength());
        TraceMsg("SEND", buffer.Span);
        int written = writer.Encode(buffer.Span);
        _outgoing.Writer.Advance(written);
        _outgoing.Writer.FlushAsync().GetAwaiter().GetResult();
    }
}
