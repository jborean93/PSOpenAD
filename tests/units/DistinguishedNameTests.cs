using PSOpenAD.LDAP;
using System;
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
}
