using PSOpenAD.Module;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Formats.Asn1;
using System.IO.Pipelines;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class PipelineLDAPSessionTests
{
    // System.IO.Pipelines stops accepting writes once the unconsumed bytes pass
    // its pause threshold (64 KiB by default). A request that large is ordinary
    // - creating a group with a few thousand members is one - and the flush the
    // writer waits on there does not complete synchronously.
    private const int LargeValueSize = 256 * 1024;

    [Test]
    public async Task WritesARequestLargerThanThePipePauseThreshold()
    {
        PipelineLDAPSession session = new();
        AsnWriter writer = new(AsnEncodingRules.BER);
        writer.WriteOctetString(new byte[LargeValueSize]);
        int encodedLength = writer.GetEncodedLength();

        Task write = Task.Run(() => session.WriteData(writer));

        // Nothing has drained the pipe yet, so the write is over the threshold:
        // it has to wait for a reader, not fail.
        await Task.Delay(250);

        long drained = 0;
        while (drained < encodedLength)
        {
            ReadResult read = await session.Outgoing.ReadAsync();
            drained += read.Buffer.Length;
            session.Outgoing.AdvanceTo(read.Buffer.End);
        }

        await write.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(drained).IsEqualTo((long)encodedLength);
    }

    [Test]
    public async Task TracesTheEncodedRequestRatherThanTheBuffer()
    {
        using MemoryStream log = new();
        using StreamWriter logWriter = new(log);
        PipelineLDAPSession session = new(writer: logWriter);

        AsnWriter writer = new(AsnEncodingRules.BER);
        writer.WriteOctetString(new byte[] { 1, 2, 3, 4 });
        byte[] expected = writer.Encode();

        session.WriteData(writer);
        logWriter.Flush();

        string[] lines = Encoding.UTF8.GetString(log.ToArray())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries);
        string? sent = lines.FirstOrDefault(l => l.StartsWith("SEND: "));

        await Assert.That(sent).IsNotNull();
        await Assert.That(Convert.FromBase64String(sent!["SEND: ".Length..].Trim()))
            .IsEquivalentTo(expected);
    }
}
