using PSOpenAD;
using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class RangedAttributeAccumulatorTests
{
    private static byte[][] Values(int count)
        => Enumerable.Range(0, count).Select(i => Encoding.UTF8.GetBytes($"v{i}")).ToArray();

    [Test]
    public async Task CompletesAfterTwoPages()
    {
        // First page as AD names it: "member;range=0-1499", 1500 values.
        RangedAttributeAccumulator acc = new("member", Values(1500), high: 1499, isFinal: false);

        await Assert.That(acc.NeedsNextPage).IsTrue();
        string request = acc.NextRequest();
        await Assert.That(request).IsEqualTo("member;range=1500-*");

        // Final page: "member;range=1500-*", 100 values.
        acc.AddPage("member;range=1500-*", Values(100));

        await Assert.That(acc.IsComplete).IsTrue();
        await Assert.That(acc.NeedsNextPage).IsFalse();
        await Assert.That(acc.Values.Length).IsEqualTo(1600);
    }

    [Test]
    public async Task StopsAtMaxPagesWhenServerNeverSendsAFinalPage()
    {
        RangedAttributeAccumulator acc = new("member", Values(100), high: 99, isFinal: false);

        int requestsIssued = 0;
        while (acc.NeedsNextPage)
        {
            string request = acc.NextRequest();
            requestsIssued++;

            // A pathological server that always answers with another 100-wide page and
            // never terminates the range with "*".
            int low = int.Parse(request.Split('=')[1].Split('-')[0]);
            int high = low + 99;
            acc.AddPage($"member;range={low}-{high}", Values(100));
        }

        await Assert.That(requestsIssued).IsEqualTo(RangedAttributeAccumulator.MaxPages);
        await Assert.That(acc.IsComplete).IsFalse();
        await Assert.That(acc.NeedsNextPage).IsFalse();
    }

    [Test]
    public async Task StopsWhenAPageReturnsNoValues()
    {
        RangedAttributeAccumulator acc = new("member", Values(1500), high: 1499, isFinal: false);

        acc.NextRequest();
        acc.AddPage("member;range=1500-*", Array.Empty<byte[]>());

        await Assert.That(acc.IsComplete).IsTrue();
        await Assert.That(acc.NeedsNextPage).IsFalse();
        await Assert.That(acc.Values.Length).IsEqualTo(1500);
    }

    [Test]
    public async Task StopsWhenTheServerHasNoMatchingPage()
    {
        RangedAttributeAccumulator acc = new("member", Values(1500), high: 1499, isFinal: false);

        acc.NextRequest();
        acc.AddPage(null, null);

        await Assert.That(acc.IsComplete).IsTrue();
        await Assert.That(acc.Values.Length).IsEqualTo(1500);
    }
}
