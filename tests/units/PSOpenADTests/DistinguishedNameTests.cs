using System;
using System.Threading.Tasks;
using PSOpenAD.LDAP;
using TUnit.Core;

namespace PSOpenADTests;

public class DistinguishedNameTests
{
    [Test]
    [Arguments("Sue, Grabbit and Runn", "Sue\\, Grabbit and Runn")]
    [Arguments("Before\rAfter", "Before\\0DAfter")]
    [Arguments("Docs, Adatum", "Docs\\, Adatum")]
    [Arguments("foo,bar", "foo\\,bar")]
    [Arguments("foo+bar", "foo\\+bar")]
    [Arguments("foo\"bar", "foo\\\"bar")]
    [Arguments("foo\\bar", "foo\\\\bar")]
    [Arguments("foo<bar", "foo\\<bar")]
    [Arguments("foo>bar", "foo\\>bar")]
    [Arguments("foo;bar", "foo\\;bar")]
    [Arguments(" foo bar", "\\ foo bar")]
    [Arguments("#foo bar", "\\#foo bar")]
    [Arguments("# foo bar", "\\# foo bar")]
    [Arguments("foo bar ", "foo bar\\ ")]
    [Arguments("foo bar  ", "foo bar \\ ")]
    [Arguments("foo bar #", "foo bar #")]
    [Arguments("foo\nbar", "foo\\0Abar")]
    [Arguments("foo\rbar", "foo\\0Dbar")]
    [Arguments("foo=bar", "foo\\3Dbar")]
    [Arguments("foo/bar", "foo\\2Fbar")]
    public async Task EscapeAttributeValue(string value, string expected)
    {
        string actual = DistinguishedName.EscapeAttributeValue(value);
        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    // Various space permutations
    [Arguments("CN=foo", 6, "CN", "foo", "foo")]
    [Arguments("cn=foo", 6, "cn", "foo", "foo")]
    [Arguments("CN= foo", 7, "CN", "foo", "foo")]
    [Arguments("CN=  foo", 8, "CN", "foo", "foo")]
    [Arguments("CN =foo", 7, "CN", "foo", "foo")]
    [Arguments("CN  =foo", 8, "CN", "foo", "foo")]
    [Arguments("CN = foo", 8, "CN", "foo", "foo")]
    [Arguments("CN  =  foo", 10, "CN", "foo", "foo")]
    [Arguments(" CN = foo", 9, "CN", "foo", "foo")]
    [Arguments("  CN = foo", 10, "CN", "foo", "foo")]
    [Arguments("CN = foo ", 9, "CN", "foo", "foo")]
    [Arguments("CN = foo  ", 10, "CN", "foo", "foo")]
    [Arguments(" CN = foo ", 10, "CN", "foo", "foo")]
    [Arguments("  CN = foo  ", 12, "CN", "foo", "foo")]
    // Escaping starting characters
    [Arguments("cn=\\#abc", 8, "cn", "#abc", "\\#abc")]
    [Arguments("cn=\\ abc", 8, "cn", " abc", "\\ abc")]
    [Arguments("cn=\\  abc", 9, "cn", "  abc", "\\  abc")]
    [Arguments("cn= \\ abc", 9, "cn", " abc", "\\ abc")]
    [Arguments("cn= \\  abc", 10, "cn", "  abc", "\\  abc")]
    [Arguments("cn=  \\ abc", 10, "cn", " abc", "\\ abc")]
    [Arguments("cn=  \\  abc", 11, "cn", "  abc", "\\  abc")]
    // Escaping literal characters
    [Arguments("cn=foo\\\\bar", 11, "cn", "foo\\bar", "foo\\\\bar")]
    [Arguments("cn=foo\\\"bar", 11, "cn", "foo\"bar", "foo\\\"bar")]
    [Arguments("cn=foo\\+bar", 11, "cn", "foo+bar", "foo\\+bar")]
    [Arguments("cn=foo\\,bar", 11, "cn", "foo,bar", "foo\\,bar")]
    [Arguments("cn=foo\\;bar", 11, "cn", "foo;bar", "foo\\;bar")]
    [Arguments("cn=foo\\<bar", 11, "cn", "foo<bar", "foo\\<bar")]
    [Arguments("cn=foo\\>bar", 11, "cn", "foo>bar", "foo\\>bar")]
    [Arguments("cn=foo\\ bar", 11, "cn", "foo bar", "foo bar")]
    [Arguments("cn=foo\\#bar", 11, "cn", "foo#bar", "foo#bar")]
    [Arguments("cn=foo\\=bar", 11, "cn", "foo=bar", "foo\\3Dbar")]
    // Escaping hex characters
    [Arguments("cn=foo\\00bar", 12, "cn", "foo\0bar", "foo\\00bar")]
    [Arguments("cn=foo\\4Ebar", 12, "cn", "fooNbar", "fooNbar")]
    [Arguments("cn=foo\\4ebar", 12, "cn", "fooNbar", "fooNbar")]
    // RFC examples
    [Arguments(
        "cn=James \\\"Jim\\\" Smith\\, III",
        28,
        "cn",
        "James \"Jim\" Smith, III",
        "James \\\"Jim\\\" Smith\\, III")]
    [Arguments(
        "CN=Before\\0dAfter",
        17,
        "CN",
        "Before\rAfter",
        "Before\\0DAfter")]
    [Arguments(
        "CN=Lu\\C4\\8Di\\C4\\87",
        18,
        "CN",
        "Lučić",
        "Lučić")]
    // OID and Hex values
    [Arguments(
        "1.3.6.1.4.1.1466.0=#FE04024869",
        30,
        "1.3.6.1.4.1.1466.0",
        "#FE04024869",
        "#FE04024869")]
    public async Task AttributeTypeAndValueParse(
        string inputString,
        int expectedRead,
        string expectedType,
        string expectedValue,
        string expectedEscapedValue)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var actualRead);

        await Assert.That(wasValid).IsTrue();
        await Assert.That(actual).IsNotNull();
        await Assert.That(actualRead).IsEqualTo(expectedRead);
        await Assert.That(actual.Type).IsEqualTo(expectedType);
        await Assert.That(actual.Value).IsEqualTo(expectedValue);
        await Assert.That(actual.EscapedValue).IsEqualTo(expectedEscapedValue);
        await Assert.That(actual.ToString()).IsEqualTo(inputString.Trim(' '));
    }

    [Test]
    [Arguments("cn=foo\\ ", 8, "cn", "foo ", "foo\\ ", "cn=foo\\ ")]
    [Arguments("cn=foo\\  ", 9, "cn", "foo ", "foo\\ ", "cn=foo\\ ")]
    [Arguments("cn=foo \\ ", 9, "cn", "foo  ", "foo \\ ", "cn=foo \\ ")]
    [Arguments("cn=foo \\  ", 10, "cn", "foo  ", "foo \\ ", "cn=foo \\ ")]
    public async Task AttributeTypeAndValueParseEscapedEndChars(
        string inputString,
        int expectedRead,
        string expectedType,
        string expectedValue,
        string expectedEscapedValue,
        string expectedToString)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var actualRead);

        await Assert.That(wasValid).IsTrue();
        await Assert.That(actual).IsNotNull();
        await Assert.That(actualRead).IsEqualTo(expectedRead);
        await Assert.That(actual.Type).IsEqualTo(expectedType);
        await Assert.That(actual.Value).IsEqualTo(expectedValue);
        await Assert.That(actual.EscapedValue).IsEqualTo(expectedEscapedValue);
        await Assert.That(actual.ToString()).IsEqualTo(expectedToString);
    }

    [Test]
    [Arguments("CN=foo,DC=domain", 6, "CN", "foo", "foo", "CN=foo")]
    [Arguments("CN=foo+DC=domain", 6, "CN", "foo", "foo", "CN=foo")]
    [Arguments("CN=foo  ,DC=domain", 8, "CN", "foo", "foo", "CN=foo")]
    [Arguments("CN=#FE04024869  ,DC=domain", 16, "CN", "#FE04024869", "#FE04024869", "CN=#FE04024869")]
    public async Task AttributeTypeAndValueParseWithExtraData(
        string inputString,
        int expectedRead,
        string expectedType,
        string expectedValue,
        string expectedEscapedValue,
        string expectedToString)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var actualRead);

        await Assert.That(wasValid).IsTrue();
        await Assert.That(actual).IsNotNull();
        await Assert.That(actualRead).IsEqualTo(expectedRead);
        await Assert.That(actual.Type).IsEqualTo(expectedType);
        await Assert.That(actual.Value).IsEqualTo(expectedValue);
        await Assert.That(actual.EscapedValue).IsEqualTo(expectedEscapedValue);
        await Assert.That(actual.ToString()).IsEqualTo(expectedToString);
    }

    [Test]
    // No separator
    [Arguments("CN")]
    // No value
    [Arguments("CN=")]
    // Type is invalid
    [Arguments("CN_DEF=value")]
    [Arguments("1CN=value")]
    [Arguments("1=value")]
    // Value starts with # but isn't valid hex
    [Arguments("cn=#")]
    [Arguments("cn=#gh")]
    [Arguments("cn=#12a")]
    // Value contains unescaped chars
    [Arguments("cn=foo\0")]
    [Arguments("cn=foo\"")]
    [Arguments("cn=foo;")]
    [Arguments("cn=foo<")]
    [Arguments("cn=foo>")]
    // Value contains invalid escape chars
    [Arguments("cn=foo\\")]
    [Arguments("cn=foo\\a")]
    [Arguments("cn=foo\\\0")]
    // Value contains invalid escape hex pairs
    [Arguments("cn=foo\\0")]
    [Arguments("cn=foo\\0g")]
    [Arguments("cn=foo\\ag")]
    public async Task AttributeTypeAndValueParseFailure(string inputString)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var _);

        await Assert.That(wasValid).IsFalse();
        await Assert.That(actual).IsNull();
    }

    [Test]
    [Arguments("foo", "foo")]
    [Arguments("Foo", "Foo")]
    [Arguments(" foo", "\\ foo")]
    [Arguments("  foo", "\\  foo")]
    [Arguments("foo ", "foo\\ ")]
    [Arguments("foo  ", "foo \\ ")]
    [Arguments("#test", "\\#test")]
    [Arguments("foo\\bar", "foo\\\\bar")]
    [Arguments("foo\0", "foo\\00")]
    public async Task CreateATVWithString(string inputString, string expectedEscapedValue)
    {
        AttributeTypeAndValue actual = new("CN", inputString);

        await Assert.That(actual.Type).IsEqualTo("CN");
        await Assert.That(actual.EscapedValue).IsEqualTo(expectedEscapedValue);
        await Assert.That(actual.IsASN1EncodedValue).IsFalse();
        await Assert.That(actual.ToString()).IsEqualTo($"CN={expectedEscapedValue}");
    }

    [Test]
    public async Task CreateATVWithByteArray()
    {
        const string expectedValue = "#0403416263";
        AttributeTypeAndValue actual = new("cn", new byte[] { 4, 3, 65, 98, 99 });

        await Assert.That(actual.Type).IsEqualTo("cn");
        await Assert.That(actual.Value).IsEqualTo(expectedValue);
        await Assert.That(actual.IsASN1EncodedValue).IsTrue();
        await Assert.That(actual.EscapedValue).IsEqualTo(expectedValue);
        await Assert.That(actual.ToString()).IsEqualTo($"cn={expectedValue}");
    }

    [Test]
    public async Task ParseRelativeDistinguishedNameSingleAttribute()
    {
        const string rdnString = "cn=foo";

        bool wasValid = RelativeDistinguishedName.TryParse(rdnString, out var actual, out var consumed);

        await Assert.That(wasValid).IsTrue();
        await Assert.That(actual).IsNotNull();
        await Assert.That(consumed).IsEqualTo(6);
        await Assert.That(actual.ToString()).IsEqualTo(rdnString);
        await Assert.That(actual.Values).HasSingleItem();
        await Assert.That(actual.Values[0].Type).IsEqualTo("cn");
        await Assert.That(actual.Values[0].Value).IsEqualTo("foo");
    }

    [Test]
    public async Task ParseRelativeDistinguishedNameMuliAttribute()
    {
        const string rdnString = "cn=foo+Name=value\\+test+other=bar";

        bool wasValid = RelativeDistinguishedName.TryParse(rdnString, out var actual, out var consumed);

        await Assert.That(wasValid).IsTrue();
        await Assert.That(actual).IsNotNull();
        await Assert.That(consumed).IsEqualTo(33);
        await Assert.That(actual.ToString()).IsEqualTo(rdnString);
        await Assert.That(actual.Values.Length).IsEqualTo(3);
        await Assert.That(actual.Values[0].Type).IsEqualTo("cn");
        await Assert.That(actual.Values[0].Value).IsEqualTo("foo");
        await Assert.That(actual.Values[1].Type).IsEqualTo("Name");
        await Assert.That(actual.Values[1].Value).IsEqualTo("value+test");
        await Assert.That(actual.Values[2].Type).IsEqualTo("other");
        await Assert.That(actual.Values[2].Value).IsEqualTo("bar");
    }

    [Test]
    public async Task ParseRelativeDistinguishedNameWithExtraData()
    {
        const string rdnString = " cn = foo + Name = value\\+test + other = bar , test=value";

        bool wasValid = RelativeDistinguishedName.TryParse(rdnString, out var actual, out var consumed);

        await Assert.That(wasValid).IsTrue();
        await Assert.That(actual).IsNotNull();
        await Assert.That(consumed).IsEqualTo(45);
        await Assert.That(actual.ToString()).IsEqualTo("cn = foo + Name = value\\+test + other = bar");
        await Assert.That(actual.Values.Length).IsEqualTo(3);
        await Assert.That(actual.Values[0].Type).IsEqualTo("cn");
        await Assert.That(actual.Values[0].Value).IsEqualTo("foo");
        await Assert.That(actual.Values[1].Type).IsEqualTo("Name");
        await Assert.That(actual.Values[1].Value).IsEqualTo("value+test");
        await Assert.That(actual.Values[2].Type).IsEqualTo("other");
        await Assert.That(actual.Values[2].Value).IsEqualTo("bar");
    }

    [Test]
    [Arguments("")]
    [Arguments("CN")]
    [Arguments("CN=")]
    [Arguments("CN=fake\\")]
    [Arguments("CN=foo+")]
    [Arguments("CN=foo+cn")]
    [Arguments("CN=foo+cn=")]
    [Arguments("CN=foo+cn=invalid\\")]
    public async Task ParseRelativeDistinguishedNameFailure(string inputString)
    {
        bool wasValid = RelativeDistinguishedName.TryParse(inputString, out var actual, out var _);

        await Assert.That(wasValid).IsFalse();
        await Assert.That(actual).IsNull();
    }

    [Test]
    public async Task CreateRelativeDistinguishedNameSingle()
    {
        const string expected = "cn=foo\\0Abar";
        RelativeDistinguishedName actual = new(new[]
        {
            new AttributeTypeAndValue("cn", "foo\nbar"),
        });

        await Assert.That(actual.Values).HasSingleItem();
        await Assert.That(actual.ToString()).IsEqualTo(expected);
    }

    [Test]
    public async Task CreateRelativeDistinguishedNameMulti()
    {
        const string expected = "cn=foo\\ +uid=123";
        RelativeDistinguishedName actual = new(new[]
        {
            new AttributeTypeAndValue("cn", "foo "),
            new AttributeTypeAndValue("uid", "123"),
        });

        await Assert.That(actual.Values.Length).IsEqualTo(2);
        await Assert.That(actual.ToString()).IsEqualTo(expected);
    }

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments(" ")]
    public async Task ParseDistinguishedNameEmpty(string? inputValue)
    {
        DistinguishedName dn = DistinguishedName.Parse(inputValue);

        await Assert.That(dn.RelativeNames).IsEmpty();
        await Assert.That(dn.ToString()).IsEqualTo("");
    }

    [Test]
    public async Task ParseDistinguishedNameOneValue()
    {
        const string dnString = "CN=foo+uid=123";
        DistinguishedName actual = DistinguishedName.Parse(dnString);

        await Assert.That(actual.RelativeNames).HasSingleItem();
        await Assert.That(actual.RelativeNames[0].Values.Length).IsEqualTo(2);
        await Assert.That(actual.ToString()).IsEqualTo(dnString);
    }

    [Test]
    public async Task ParseDistinguishedNameMultiValue()
    {
        const string dnString = " CN = foo  + uid = 123  ,  dc= domain  ,dc= test  ";
        const string expectedRdn1 = "CN = foo  + uid = 123";
        const string expectedRdn2 = "dc= domain  ";
        const string expectedRdn3 = "dc= test";

        DistinguishedName actual = DistinguishedName.Parse(dnString);

        await Assert.That(actual.RelativeNames.Length).IsEqualTo(3);
        await Assert.That(actual.ToString()).IsEqualTo(dnString);

        await Assert.That(actual.RelativeNames[0].Values.Length).IsEqualTo(2);
        await Assert.That(actual.RelativeNames[0].Values[0].Type).IsEqualTo("CN");
        await Assert.That(actual.RelativeNames[0].Values[0].Value).IsEqualTo("foo");
        await Assert.That(actual.RelativeNames[0].Values[1].Type).IsEqualTo("uid");
        await Assert.That(actual.RelativeNames[0].Values[1].Value).IsEqualTo("123");
        await Assert.That(actual.RelativeNames[0].ToString()).IsEqualTo(expectedRdn1);

        await Assert.That(actual.RelativeNames[1].Values).HasSingleItem();
        await Assert.That(actual.RelativeNames[1].Values[0].Type).IsEqualTo("dc");
        await Assert.That(actual.RelativeNames[1].Values[0].Value).IsEqualTo("domain");
        await Assert.That(actual.RelativeNames[1].ToString()).IsEqualTo(expectedRdn2);

        await Assert.That(actual.RelativeNames[2].Values).HasSingleItem();
        await Assert.That(actual.RelativeNames[2].Values[0].Type).IsEqualTo("dc");
        await Assert.That(actual.RelativeNames[2].Values[0].Value).IsEqualTo("test");
        await Assert.That(actual.RelativeNames[2].ToString()).IsEqualTo(expectedRdn3);
    }

    [Test]
    [Arguments("CN=foo\\")]
    [Arguments("CN=foo+")]
    [Arguments("CN=foo,DC")]
    public async Task ParseDistinguishedNameFail(string inputString)
    {
        var ex = await Assert.That(() => DistinguishedName.Parse(inputString)).Throws<ArgumentException>();

        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo($"The input string '{inputString}' was not a valid DistinguishedName (Parameter 'dn')");
    }

    [Test]
    public async Task CreateDistinguishedNameSingle()
    {
        const string expected = "cn=foo";

        DistinguishedName actual = new(new[]
        {
            new RelativeDistinguishedName(new[] { new AttributeTypeAndValue("cn", "foo") }),
        });

        await Assert.That(actual.ToString()).IsEqualTo(expected);
    }

    [Test]
    public async Task CreateDistinguishedNameMulti()
    {
        const string expected = "cn=foo+uid=123,dc=domain";

        DistinguishedName actual = new(new[]
        {
            new RelativeDistinguishedName(new[]
            {
                new AttributeTypeAndValue("cn", "foo"),
                new AttributeTypeAndValue("uid", "123"),
            }),
            new RelativeDistinguishedName(new[]
            {
                new AttributeTypeAndValue("dc", "domain"),
            }),
        });

        await Assert.That(actual.ToString()).IsEqualTo(expected);
    }
}
