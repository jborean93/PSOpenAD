using System;
using PSOpenAD.LDAP;
using Xunit;

namespace PSOpenADTests;

public class DistinguishedNameTests
{
    [Theory]
    [InlineData("Sue, Grabbit and Runn", "Sue\\, Grabbit and Runn")]
    [InlineData("Before\rAfter", "Before\\0DAfter")]
    [InlineData("Docs, Adatum", "Docs\\, Adatum")]
    [InlineData("foo,bar", "foo\\,bar")]
    [InlineData("foo+bar", "foo\\+bar")]
    [InlineData("foo\"bar", "foo\\\"bar")]
    [InlineData("foo\\bar", "foo\\\\bar")]
    [InlineData("foo<bar", "foo\\<bar")]
    [InlineData("foo>bar", "foo\\>bar")]
    [InlineData("foo;bar", "foo\\;bar")]
    [InlineData(" foo bar", "\\ foo bar")]
    [InlineData("#foo bar", "\\#foo bar")]
    [InlineData("# foo bar", "\\# foo bar")]
    [InlineData("foo bar ", "foo bar\\ ")]
    [InlineData("foo bar  ", "foo bar \\ ")]
    [InlineData("foo bar #", "foo bar #")]
    [InlineData("foo\nbar", "foo\\0Abar")]
    [InlineData("foo\rbar", "foo\\0Dbar")]
    [InlineData("foo=bar", "foo\\3Dbar")]
    [InlineData("foo/bar", "foo\\2Fbar")]
    public void EscapeAttributeValue(string value, string expected)
    {
        string actual = DistinguishedName.EscapeAttributeValue(value);
        Assert.Equal(expected, actual);
    }

    [Theory]
    // Various space permutations
    [InlineData("CN=foo", 6, "CN", "foo", "foo")]
    [InlineData("cn=foo", 6, "cn", "foo", "foo")]
    [InlineData("CN= foo", 7, "CN", "foo", "foo")]
    [InlineData("CN=  foo", 8, "CN", "foo", "foo")]
    [InlineData("CN =foo", 7, "CN", "foo", "foo")]
    [InlineData("CN  =foo", 8, "CN", "foo", "foo")]
    [InlineData("CN = foo", 8, "CN", "foo", "foo")]
    [InlineData("CN  =  foo", 10, "CN", "foo", "foo")]
    [InlineData(" CN = foo", 9, "CN", "foo", "foo")]
    [InlineData("  CN = foo", 10, "CN", "foo", "foo")]
    [InlineData("CN = foo ", 9, "CN", "foo", "foo")]
    [InlineData("CN = foo  ", 10, "CN", "foo", "foo")]
    [InlineData(" CN = foo ", 10, "CN", "foo", "foo")]
    [InlineData("  CN = foo  ", 12, "CN", "foo", "foo")]
    // Escaping starting characters
    [InlineData("cn=\\#abc", 8, "cn", "#abc", "\\#abc")]
    [InlineData("cn=\\ abc", 8, "cn", " abc", "\\ abc")]
    [InlineData("cn=\\  abc", 9, "cn", "  abc", "\\  abc")]
    [InlineData("cn= \\ abc", 9, "cn", " abc", "\\ abc")]
    [InlineData("cn= \\  abc", 10, "cn", "  abc", "\\  abc")]
    [InlineData("cn=  \\ abc", 10, "cn", " abc", "\\ abc")]
    [InlineData("cn=  \\  abc", 11, "cn", "  abc", "\\  abc")]
    // Escaping literal characters
    [InlineData("cn=foo\\\\bar", 11, "cn", "foo\\bar", "foo\\\\bar")]
    [InlineData("cn=foo\\\"bar", 11, "cn", "foo\"bar", "foo\\\"bar")]
    [InlineData("cn=foo\\+bar", 11, "cn", "foo+bar", "foo\\+bar")]
    [InlineData("cn=foo\\,bar", 11, "cn", "foo,bar", "foo\\,bar")]
    [InlineData("cn=foo\\;bar", 11, "cn", "foo;bar", "foo\\;bar")]
    [InlineData("cn=foo\\<bar", 11, "cn", "foo<bar", "foo\\<bar")]
    [InlineData("cn=foo\\>bar", 11, "cn", "foo>bar", "foo\\>bar")]
    [InlineData("cn=foo\\ bar", 11, "cn", "foo bar", "foo bar")]
    [InlineData("cn=foo\\#bar", 11, "cn", "foo#bar", "foo#bar")]
    [InlineData("cn=foo\\=bar", 11, "cn", "foo=bar", "foo\\3Dbar")]
    // Escaping hex characters
    [InlineData("cn=foo\\00bar", 12, "cn", "foo\0bar", "foo\\00bar")]
    [InlineData("cn=foo\\4Ebar", 12, "cn", "fooNbar", "fooNbar")]
    [InlineData("cn=foo\\4ebar", 12, "cn", "fooNbar", "fooNbar")]
    // RFC examples
    [InlineData(
        "cn=James \\\"Jim\\\" Smith\\, III",
        28,
        "cn",
        "James \"Jim\" Smith, III",
        "James \\\"Jim\\\" Smith\\, III")]
    [InlineData(
        "CN=Before\\0dAfter",
        17,
        "CN",
        "Before\rAfter",
        "Before\\0DAfter")]
    [InlineData(
        "CN=Lu\\C4\\8Di\\C4\\87",
        18,
        "CN",
        "Lučić",
        "Lučić")]
    // OID and Hex values
    [InlineData(
        "1.3.6.1.4.1.1466.0=#FE04024869",
        30,
        "1.3.6.1.4.1.1466.0",
        "#FE04024869",
        "#FE04024869")]
    public void AttributeTypeAndValueParse(
        string inputString,
        int expectedRead,
        string expectedType,
        string expectedValue,
        string expectedEscapedValue)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var actualRead);

        Assert.True(wasValid);
        Assert.NotNull(actual);
        Assert.Equal(expectedRead, actualRead);
        Assert.Equal(expectedType, actual.Type);
        Assert.Equal(expectedValue, actual.Value);
        Assert.Equal(expectedEscapedValue, actual.EscapedValue);
        Assert.Equal(inputString.Trim(' '), actual.ToString());
    }

    [Theory]
    [InlineData("cn=foo\\ ", 8, "cn", "foo ", "foo\\ ", "cn=foo\\ ")]
    [InlineData("cn=foo\\  ", 9, "cn", "foo ", "foo\\ ", "cn=foo\\ ")]
    [InlineData("cn=foo \\ ", 9, "cn", "foo  ", "foo \\ ", "cn=foo \\ ")]
    [InlineData("cn=foo \\  ", 10, "cn", "foo  ", "foo \\ ", "cn=foo \\ ")]
    public void AttributeTypeAndValueParseEscapedEndChars(
        string inputString,
        int expectedRead,
        string expectedType,
        string expectedValue,
        string expectedEscapedValue,
        string expectedToString)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var actualRead);

        Assert.True(wasValid);
        Assert.NotNull(actual);
        Assert.Equal(expectedRead, actualRead);
        Assert.Equal(expectedType, actual.Type);
        Assert.Equal(expectedValue, actual.Value);
        Assert.Equal(expectedEscapedValue, actual.EscapedValue);
        Assert.Equal(expectedToString, actual.ToString());
    }

    [Theory]
    [InlineData("CN=foo,DC=domain", 6, "CN", "foo", "foo", "CN=foo")]
    [InlineData("CN=foo+DC=domain", 6, "CN", "foo", "foo", "CN=foo")]
    [InlineData("CN=foo  ,DC=domain", 8, "CN", "foo", "foo", "CN=foo")]
    [InlineData("CN=#FE04024869  ,DC=domain", 16, "CN", "#FE04024869", "#FE04024869", "CN=#FE04024869")]
    public void AttributeTypeAndValueParseWithExtraData(
        string inputString,
        int expectedRead,
        string expectedType,
        string expectedValue,
        string expectedEscapedValue,
        string expectedToString)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var actualRead);

        Assert.True(wasValid);
        Assert.NotNull(actual);
        Assert.Equal(expectedRead, actualRead);
        Assert.Equal(expectedType, actual.Type);
        Assert.Equal(expectedValue, actual.Value);
        Assert.Equal(expectedEscapedValue, actual.EscapedValue);
        Assert.Equal(expectedToString, actual.ToString());
    }

    [Theory]
    // No separator
    [InlineData("CN")]
    // No value
    [InlineData("CN=")]
    // Type is invalid
    [InlineData("CN_DEF=value")]
    [InlineData("1CN=value")]
    [InlineData("1=value")]
    // Value starts with # but isn't valid hex
    [InlineData("cn=#")]
    [InlineData("cn=#gh")]
    [InlineData("cn=#12a")]
    // Value contains unescaped chars
    [InlineData("cn=foo\0")]
    [InlineData("cn=foo\"")]
    [InlineData("cn=foo;")]
    [InlineData("cn=foo<")]
    [InlineData("cn=foo>")]
    // Value contains invalid escape chars
    [InlineData("cn=foo\\")]
    [InlineData("cn=foo\\a")]
    [InlineData("cn=foo\\\0")]
    // Value contains invalid escape hex pairs
    [InlineData("cn=foo\\0")]
    [InlineData("cn=foo\\0g")]
    [InlineData("cn=foo\\ag")]
    public void AttributeTypeAndValueParseFailure(string inputString)
    {
        bool wasValid = AttributeTypeAndValue.TryParse(inputString, out var actual, out var _);

        Assert.False(wasValid);
        Assert.Null(actual);
    }

    [Theory]
    [InlineData("foo", "foo")]
    [InlineData("Foo", "Foo")]
    [InlineData(" foo", "\\ foo")]
    [InlineData("  foo", "\\  foo")]
    [InlineData("foo ", "foo\\ ")]
    [InlineData("foo  ", "foo \\ ")]
    [InlineData("#test", "\\#test")]
    [InlineData("foo\\bar", "foo\\\\bar")]
    [InlineData("foo\0", "foo\\00")]
    public void CreateATVWithString(string inputString, string expectedEscapedValue)
    {
        AttributeTypeAndValue actual = new("CN", inputString);

        Assert.Equal("CN", actual.Type);
        Assert.Equal(expectedEscapedValue, actual.EscapedValue);
        Assert.False(actual.IsASN1EncodedValue);
        Assert.Equal($"CN={expectedEscapedValue}", actual.ToString());
    }

    [Fact]
    public void CreateATVWithByteArray()
    {
        const string expectedValue = "#0403416263";
        AttributeTypeAndValue actual = new("cn", new byte[] { 4, 3, 65, 98, 99 });

        Assert.Equal("cn", actual.Type);
        Assert.Equal(expectedValue, actual.Value);
        Assert.True(actual.IsASN1EncodedValue);
        Assert.Equal(expectedValue, actual.EscapedValue);
        Assert.Equal($"cn={expectedValue}", actual.ToString());
    }

    [Fact]
    public void ParseRelativeDistinguishedNameSingleAttribute()
    {
        const string rdnString = "cn=foo";

        bool wasValid = RelativeDistinguishedName.TryParse(rdnString, out var actual, out var consumed);

        Assert.True(wasValid);
        Assert.NotNull(actual);
        Assert.Equal(6, consumed);
        Assert.Equal(rdnString, actual.ToString());
        Assert.Single(actual.Values);
        Assert.Equal("cn", actual.Values[0].Type);
        Assert.Equal("foo", actual.Values[0].Value);
    }

    [Fact]
    public void ParseRelativeDistinguishedNameMuliAttribute()
    {
        const string rdnString = "cn=foo+Name=value\\+test+other=bar";

        bool wasValid = RelativeDistinguishedName.TryParse(rdnString, out var actual, out var consumed);

        Assert.True(wasValid);
        Assert.NotNull(actual);
        Assert.Equal(33, consumed);
        Assert.Equal(rdnString, actual.ToString());
        Assert.Equal(3, actual.Values.Length);
        Assert.Equal("cn", actual.Values[0].Type);
        Assert.Equal("foo", actual.Values[0].Value);
        Assert.Equal("Name", actual.Values[1].Type);
        Assert.Equal("value+test", actual.Values[1].Value);
        Assert.Equal("other", actual.Values[2].Type);
        Assert.Equal("bar", actual.Values[2].Value);
    }

    [Fact]
    public void ParseRelativeDistinguishedNameWithExtraData()
    {
        const string rdnString = " cn = foo + Name = value\\+test + other = bar , test=value";

        bool wasValid = RelativeDistinguishedName.TryParse(rdnString, out var actual, out var consumed);

        Assert.True(wasValid);
        Assert.NotNull(actual);
        Assert.Equal(45, consumed);
        Assert.Equal("cn = foo + Name = value\\+test + other = bar", actual.ToString());
        Assert.Equal(3, actual.Values.Length);
        Assert.Equal("cn", actual.Values[0].Type);
        Assert.Equal("foo", actual.Values[0].Value);
        Assert.Equal("Name", actual.Values[1].Type);
        Assert.Equal("value+test", actual.Values[1].Value);
        Assert.Equal("other", actual.Values[2].Type);
        Assert.Equal("bar", actual.Values[2].Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("CN")]
    [InlineData("CN=")]
    [InlineData("CN=fake\\")]
    [InlineData("CN=foo+")]
    [InlineData("CN=foo+cn")]
    [InlineData("CN=foo+cn=")]
    [InlineData("CN=foo+cn=invalid\\")]
    public void ParseRelativeDistinguishedNameFailure(string inputString)
    {
        bool wasValid = RelativeDistinguishedName.TryParse(inputString, out var actual, out var _);

        Assert.False(wasValid);
        Assert.Null(actual);
    }

    [Fact]
    public void CreateRelativeDistinguishedNameSingle()
    {
        const string expected = "cn=foo\\0Abar";
        RelativeDistinguishedName actual = new(new[]
        {
            new AttributeTypeAndValue("cn", "foo\nbar"),
        });

        Assert.Single(actual.Values);
        Assert.Equal(expected, actual.ToString());
    }

    [Fact]
    public void CreateRelativeDistinguishedNameMulti()
    {
        const string expected = "cn=foo\\ +uid=123";
        RelativeDistinguishedName actual = new(new[]
        {
            new AttributeTypeAndValue("cn", "foo "),
            new AttributeTypeAndValue("uid", "123"),
        });

        Assert.Equal(2, actual.Values.Length);
        Assert.Equal(expected, actual.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public void ParseDistinguishedNameEmpty(string? inputValue)
    {
        DistinguishedName dn = DistinguishedName.Parse(inputValue);

        Assert.Empty(dn.RelativeNames);
        Assert.Equal("", dn.ToString());
    }

    [Fact]
    public void ParseDistinguishedNameOneValue()
    {
        const string dnString = "CN=foo+uid=123";
        DistinguishedName actual = DistinguishedName.Parse(dnString);

        Assert.Single(actual.RelativeNames);
        Assert.Equal(2, actual.RelativeNames[0].Values.Length);
        Assert.Equal(dnString, actual.ToString());
    }

    [Fact]
    public void ParseDistinguishedNameMultiValue()
    {
        const string dnString = " CN = foo  + uid = 123  ,  dc= domain  ,dc= test  ";
        const string expectedRdn1 = "CN = foo  + uid = 123";
        const string expectedRdn2 = "dc= domain  ";
        const string expectedRdn3 = "dc= test";

        DistinguishedName actual = DistinguishedName.Parse(dnString);

        Assert.Equal(3, actual.RelativeNames.Length);
        Assert.Equal(dnString, actual.ToString());

        Assert.Equal(2, actual.RelativeNames[0].Values.Length);
        Assert.Equal("CN", actual.RelativeNames[0].Values[0].Type);
        Assert.Equal("foo", actual.RelativeNames[0].Values[0].Value);
        Assert.Equal("uid", actual.RelativeNames[0].Values[1].Type);
        Assert.Equal("123", actual.RelativeNames[0].Values[1].Value);
        Assert.Equal(expectedRdn1, actual.RelativeNames[0].ToString());

        Assert.Single(actual.RelativeNames[1].Values);
        Assert.Equal("dc", actual.RelativeNames[1].Values[0].Type);
        Assert.Equal("domain", actual.RelativeNames[1].Values[0].Value);
        Assert.Equal(expectedRdn2, actual.RelativeNames[1].ToString());

        Assert.Single(actual.RelativeNames[2].Values);
        Assert.Equal("dc", actual.RelativeNames[2].Values[0].Type);
        Assert.Equal("test", actual.RelativeNames[2].Values[0].Value);
        Assert.Equal(expectedRdn3, actual.RelativeNames[2].ToString());
    }

    [Theory]
    [InlineData("CN=foo\\")]
    [InlineData("CN=foo+")]
    [InlineData("CN=foo,DC")]
    public void ParseDistinguishedNameFail(string inputString)
    {
        var ex = Assert.Throws<ArgumentException>(() => DistinguishedName.Parse(inputString));

        Assert.Equal($"The input string '{inputString}' was not a valid DistinguishedName (Parameter 'dn')", ex.Message);
    }

    [Fact]
    public void CreateDistinguishedNameSingle()
    {
        const string expected = "cn=foo";

        DistinguishedName actual = new(new[]
        {
            new RelativeDistinguishedName(new[] { new AttributeTypeAndValue("cn", "foo") }),
        });

        Assert.Equal(expected, actual.ToString());
    }

    [Fact]
    public void CreateDistinguishedNameMulti()
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

        Assert.Equal(expected, actual.ToString());
    }
}
