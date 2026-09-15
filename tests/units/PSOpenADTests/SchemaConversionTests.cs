using PSOpenAD;
using System;
using System.Management.Automation;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class SchemaConversionTests
{
    [Test]
    public async Task RawByteArrayStaysBinary()
    {
        byte[] input = new byte[] { 1, 0, 4, 128, 20, 0, 0, 0 };

        byte[] actual = SchemaMetadata.ConvertToRawAttributeValue(input);

        await Assert.That(Convert.ToBase64String(actual))
            .IsEqualTo(Convert.ToBase64String(input));
    }

    [Test]
    public async Task PSObjectWrappedByteArrayStaysBinary()
    {
        byte[] input = new byte[] { 1, 0, 4, 128, 20, 0, 0, 0 };
        object wrapped = PSObject.AsPSObject(input);

        byte[] actual = SchemaMetadata.ConvertToRawAttributeValue(wrapped);

        await Assert.That(Convert.ToBase64String(actual))
            .IsEqualTo(Convert.ToBase64String(input));
    }

    [Test]
    public async Task PSObjectWrappedByteArrayCollectionIsOneValue()
    {
        byte[] input = new byte[] { 1, 0, 4, 128 };
        object wrapped = PSObject.AsPSObject(input);

        byte[][] actual = SchemaMetadata.ConvertToRawAttributeCollection(wrapped);

        await Assert.That(actual.Length).IsEqualTo(1);
        await Assert.That(Convert.ToBase64String(actual[0]))
            .IsEqualTo(Convert.ToBase64String(input));
    }

    [Test]
    public async Task PSObjectWrappedStringStillConvertsToUtf8()
    {
        object wrapped = PSObject.AsPSObject("hello");

        byte[] actual = SchemaMetadata.ConvertToRawAttributeValue(wrapped);

        await Assert.That(System.Text.Encoding.UTF8.GetString(actual)).IsEqualTo("hello");
    }
}
