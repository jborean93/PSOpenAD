using PSOpenAD;
using PSOpenAD.Security;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TUnit.Core;

namespace PSOpenADTests;

public class SchemaMetadataTests
{
    public enum ByteEnum : byte
    {
        Value1 = 1,
    }

    public enum SByteEnum : sbyte
    {
        Value1 = 1,
    }

    public enum ShortEnum : short
    {
        Value1 = 1,
    }

    public enum UShortEnum : ushort
    {
        Value1 = 1,
    }

    public enum IntEnum : int
    {
        Value1 = 1,
    }

    public enum UIntEnum : uint
    {
        Value1 = 1,
    }

    public enum LongEnum : long
    {
        Value1 = 1,
    }

    public enum ULongEnum : ulong
    {
        Value1 = 1,
    }

    [Test]
    public async Task ConvertNullToRawAttributeCollection()
    {
        string[] expected = Array.Empty<string>();

        byte[][] result = SchemaMetadata.ConvertToRawAttributeCollection(null);
        string[] actual = result.Select(b => Convert.ToBase64String(b)).ToArray();

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertSingleByteArrayToRawAttributeCollection()
    {
        string[] expected = new [] { "AAECAw==" };

        byte[][] result = SchemaMetadata.ConvertToRawAttributeCollection(new byte[] { 0, 1, 2, 3});
        string[] actual = result.Select(b => Convert.ToBase64String(b)).ToArray();

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertMultipleByteArrayToRawAttributeCollection()
    {
        string[] expected = new [] { "AAECAw==", "BAUGBw==" };

        byte[][] result = SchemaMetadata.ConvertToRawAttributeCollection(
            new byte[][]
            {
                new byte[] { 0, 1, 2, 3 },
                new byte[] { 4, 5, 6, 7 },
            });
        string[] actual = result.Select(b => Convert.ToBase64String(b)).ToArray();

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertStringToRawAttributeCollection()
    {
        string[] expected = new[] { "Café 1" };

        byte[][] result = SchemaMetadata.ConvertToRawAttributeCollection("Café 1");
        string[] actual = result.Select(b => Encoding.UTF8.GetString(b)).ToArray();

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertMultipleStringsToRawAttributeCollection()
    {
        string[] expected = new[] { "Café 1", "Café 2" };

        List<string> values = new List<string>()
        {
            "Café 1",
            "Café 2"
        };
        byte[][] result = SchemaMetadata.ConvertToRawAttributeCollection(values);
        string[] actual = result.Select(b => Encoding.UTF8.GetString(b)).ToArray();

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertNullToRawAttributeValue()
    {
        const string expected = "";

        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(null);
        string actual = Encoding.UTF8.GetString(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments(true, "TRUE")]
    [Arguments(false, "FALSE")]
    public async Task ConvertBoolToRawAttributeValue(bool value, string expected)
    {
        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Encoding.UTF8.GetString(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertCommonSecurityDescriptorToRawAttributeValue()
    {
        CommonSecurityDescriptor sd = new()
        {
            Owner = new("S-1-5-18"),
            DiscretionaryAcl = new(AclRevision.Revision),
        };
        sd.DiscretionaryAcl.Add(new Ace(
            AceType.AccessAllowed,
            AceFlags.None,
            ActiveDirectoryRights.CreateChild,
            new SecurityIdentifier("S-1-1-0"),
            null));

        string expected = Convert.ToBase64String(sd.ToByteArray());

        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(sd);
        string actual = Convert.ToBase64String(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments(ByteEnum.Value1, "1")]
    [Arguments(SByteEnum.Value1, "1")]
    [Arguments(ShortEnum.Value1, "1")]
    [Arguments(UShortEnum.Value1, "1")]
    [Arguments(IntEnum.Value1, "1")]
    [Arguments(UIntEnum.Value1, "1")]
    [Arguments(LongEnum.Value1, "1")]
    [Arguments(ULongEnum.Value1, "1")]
    public async Task ConvertEnumToRawAttributeValue(Enum value, string expected)
    {
        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Encoding.UTF8.GetString(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertDateTimeToRawAttributeValue()
    {
        const string expected = "116444736000000000";

        DateTime value = new(1970, 1, 1);
        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Encoding.UTF8.GetString(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertDateTimeOffsetToRawAttributeValue()
    {
        const string expected = "116444736000000000";

        DateTimeOffset value = new(1970, 1, 1, 1, 0, 0, new TimeSpan(1, 0, 0));
        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Encoding.UTF8.GetString(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertGuidToRawAttributeValue()
    {
        Guid value = Guid.NewGuid();
        string expected = Convert.ToBase64String(value.ToByteArray());

        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Convert.ToBase64String(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertSecurityIdentifierToRawAttributeValue()
    {
        SecurityIdentifier sid = new("S-1-5-18");

        string expected = Convert.ToBase64String(sid.ToByteArray());

        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(sid);
        string actual = Convert.ToBase64String(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertTimeSpanToRawAttributeValue()
    {
        const string expected = "1024";

        TimeSpan value = new(1024);
        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Encoding.UTF8.GetString(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ConvertCertificateToAttributeValue()
    {
        CertificateRequest certReq = new(
            "CN=Subject",
            ECDsa.Create(ECCurve.NamedCurves.nistP256),
            HashAlgorithmName.SHA256);
        DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        DateTimeOffset notAfter = notBefore.AddDays(30);

        X509Certificate2 value = certReq.CreateSelfSigned(notBefore, notAfter);
        string expected = Convert.ToBase64String(value.Export(X509ContentType.Cert));

        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Convert.ToBase64String(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("Café", "Café")]
    [Arguments(0, "0")]
    [Arguments(1, "1")]
    [Arguments(-1, "-1")]
    public async Task ConvertOtherToRawAttributeValue(object value, string expected)
    {
        byte[] result = SchemaMetadata.ConvertToRawAttributeValue(value);
        string actual = Encoding.UTF8.GetString(result);

        await Assert.That(actual).IsEquivalentTo(expected);
    }
}
