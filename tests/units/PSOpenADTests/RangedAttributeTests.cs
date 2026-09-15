using PSOpenAD;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class RangedAttributeTests
{
    [Test]
    public async Task ParsesFirstPage()
    {
        bool ok = RangedAttribute.TryParse("member;range=0-1499",
            out string baseName, out int low, out int high, out bool isFinal);

        await Assert.That(ok).IsTrue();
        await Assert.That(baseName).IsEqualTo("member");
        await Assert.That(low).IsEqualTo(0);
        await Assert.That(high).IsEqualTo(1499);
        await Assert.That(isFinal).IsFalse();
    }

    [Test]
    public async Task ParsesFinalPage()
    {
        bool ok = RangedAttribute.TryParse("member;range=1500-*",
            out string baseName, out int low, out int high, out bool isFinal);

        await Assert.That(ok).IsTrue();
        await Assert.That(baseName).IsEqualTo("member");
        await Assert.That(low).IsEqualTo(1500);
        await Assert.That(high).IsEqualTo(-1);
        await Assert.That(isFinal).IsTrue();
    }

    [Test]
    public async Task IgnoresPlainAttribute()
    {
        bool ok = RangedAttribute.TryParse("member",
            out string _1, out int _2, out int _3, out bool _4);

        await Assert.That(ok).IsFalse();
    }

    [Test]
    public async Task IgnoresOtherAttributeOptions()
    {
        bool ok = RangedAttribute.TryParse("userCertificate;binary",
            out string _1, out int _2, out int _3, out bool _4);

        await Assert.That(ok).IsFalse();
    }

    [Test]
    public async Task BuildsTheNextRequest()
    {
        string next = RangedAttribute.NextRequest("member", 1499);

        await Assert.That(next).IsEqualTo("member;range=1500-*");
    }
}
