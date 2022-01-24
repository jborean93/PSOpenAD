using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class AbnfDecoderTests
{
    [Theory]
    [InlineData(" ", " ")]
    [InlineData("  ", "  ")]
    [InlineData(" testing", " ")]
    [InlineData("    abc def", "    ")]
    public static void TryParseSP(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseSP(data, out var actualSP, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualSP);
        Assert.Equal(expected.Length, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a ")]
    public static void TryParseSPFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseSP(data, out var actualSP, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualSP);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData(" ", " ")]
    [InlineData("  ", "  ")]
    [InlineData(" testing", " ")]
    [InlineData("    abc def", "    ")]
    [InlineData("", "")]
    [InlineData("a ", "")]
    public static void TryParseWSP(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseWSP(data, out var actualSP, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualSP);
        Assert.Equal(expected.Length, charsConsumed);
    }

    [Theory]
    [InlineData("a", "a")]
    [InlineData("a ", "a")]
    [InlineData("abc", "abc")]
    [InlineData("abc ", "abc")]
    [InlineData("ABC", "ABC")]
    [InlineData("ABC ", "ABC")]
    [InlineData("a123", "a123")]
    [InlineData("a-123-", "a-123-")]
    [InlineData("a-123-_ ", "a-123-")]
    [InlineData("A23 ", "A23")]
    [InlineData("café ", "caf")]
    public static void TryParseKeyString(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseKeyString(data, out var actualKS, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualKS);
        Assert.Equal(expected.Length, charsConsumed);
    }

    [Theory]
    [InlineData(" abc")]
    [InlineData("1abc")]
    [InlineData("-abc")]
    [InlineData("0")]
    [InlineData("-")]
    [InlineData("ést")]
    public static void TryParseKeyStringFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseKeyString(data, out var actualSP, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualSP);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("a", "a", 1)]
    [InlineData("a ", "a ", 2)]
    [InlineData("abc", "abc", 3)]
    [InlineData("abc ", "abc ", 4)]
    [InlineData("abc\\ ", "abc", 3)]
    [InlineData("abc' ", "abc", 3)]
    [InlineData("ABC", "ABC", 3)]
    [InlineData("ABC ", "ABC ", 4)]
    [InlineData("a123", "a123", 4)]
    [InlineData("a-123-", "a-123-", 6)]
    [InlineData("a-123-_ ", "a-123-_ ", 8)]
    [InlineData("A23 ", "A23 ", 4)]
    [InlineData("café ", "café ", 5)]
    [InlineData("testing\\5", "testing", 7)]
    [InlineData("testing\\5' ", "testing", 7)]
    [InlineData("testing\\5c", "testing\\", 10)]
    [InlineData("testing\\5c' abc", "testing\\", 10)]
    [InlineData("testing\\27 abc\\5c\\27 ' ", "testing' abc\\' ", 21)]
    public static void TryParseEscapedUTF8String(string data, string expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseEscapedUTF8String(data, out var actualKS, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualKS);
        Assert.Equal(expectedConsumed, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("'")]
    [InlineData("\\")]
    public static void TryParseEscapedUTF8StringFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseEscapedUTF8String(data, out var actualSP, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualSP);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("0", "0")]
    [InlineData("01", "0")]
    [InlineData("1", "1")]
    [InlineData("10", "10")]
    [InlineData("101 01", "101")]
    [InlineData("101a", "101")]
    public static void TryParseNumber(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseNumber(data, out var actualNumber, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualNumber);
        Assert.Equal(expected.Length, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a1")]
    public static void TryParseNumberFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseNumber(data, out var actualNumber, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualNumber);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("0.0", "0.0")]
    [InlineData("1.0", "1.0")]
    [InlineData("1.01", "1.0")]
    [InlineData("1.1", "1.1")]
    [InlineData("1.1 ", "1.1")]
    [InlineData("1.1.", "1.1")]
    [InlineData("1.1.a", "1.1")]
    [InlineData("1.1. ", "1.1")]
    [InlineData("70978.0", "70978.0")]
    [InlineData("112.325423.0.91.12.932", "112.325423.0.91.12.932")]
    public static void TryParseNumericOid(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseNumericOid(data, out var actualNumericOid, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualNumericOid);
        Assert.Equal(expected.Length, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a1")]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("1")]
    [InlineData("1.")]
    public static void TryParseNumericOidFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseNumericOid(data, out var actualNumericOid, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualNumericOid);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("1.0", new[] { "1.0" }, 3)]
    [InlineData("( 1.29.1 )", new[] { "1.29.1" }, 10)]
    [InlineData("(  1.29.1 )", new[] { "1.29.1" }, 11)]
    [InlineData("( 1.29.1  )", new[] { "1.29.1" }, 11)]
    [InlineData("(  1.29.1  )", new[] { "1.29.1" }, 12)]
    [InlineData("(3.85$129.3.0)", new[] { "3.85", "129.3.0" }, 14)]
    [InlineData("( 3.85$129.3.0)", new[] { "3.85", "129.3.0" }, 15)]
    [InlineData("(3.85$129.3.0  )", new[] { "3.85", "129.3.0" }, 16)]
    [InlineData("(3.85   $129.3.0)", new[] { "3.85", "129.3.0" }, 17)]
    [InlineData("(3.85$ 129.3.0)", new[] { "3.85", "129.3.0" }, 15)]
    public static void TryParseOids(string data, string[] expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseOids(data, out var actualOids, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualOids);
        Assert.Equal(expectedConsumed, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("01")]
    [InlineData("1")]
    [InlineData("1.")]
    [InlineData("(1.2 | 3.4)")]
    [InlineData("(1.2 $ -abc)")]
    public static void TryParseOidsFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseOids(data, out var actualOids, out var charsConsumed);

        Assert.False(actual);
        Assert.Empty(actualOids);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("0.0", "0.0")]
    [InlineData("1.0", "1.0")]
    [InlineData("1.01", "1.0")]
    [InlineData("1.1", "1.1")]
    [InlineData("1.1 ", "1.1")]
    [InlineData("1.1.", "1.1")]
    [InlineData("1.1.a", "1.1")]
    [InlineData("1.1. ", "1.1")]
    [InlineData("70978.0", "70978.0")]
    [InlineData("112.325423.0.91.12.932", "112.325423.0.91.12.932")]
    [InlineData("a", "a")]
    [InlineData("a ", "a")]
    [InlineData("abc", "abc")]
    [InlineData("abc ", "abc")]
    [InlineData("ABC", "ABC")]
    [InlineData("ABC ", "ABC")]
    [InlineData("a123", "a123")]
    [InlineData("a-123-", "a-123-")]
    [InlineData("a-123-_ ", "a-123-")]
    [InlineData("A23 ", "A23")]
    [InlineData("café ", "caf")]
    public static void TryParseOid(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseOid(data, out var actualOid, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualOid);
        Assert.Equal(expected.Length, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("1")]
    [InlineData("1.")]
    [InlineData(" abc")]
    [InlineData("1abc")]
    [InlineData("-abc")]
    [InlineData("-")]
    [InlineData("ést")]
    public static void TryParseOidFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseOid(data, out var actualNumericOid, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualNumericOid);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("1.2", "1.2", null, 3)]
    [InlineData("1.2{", "1.2", null, 3)]
    [InlineData("1.2{0", "1.2", null, 3)]
    [InlineData("1.2{}", "1.2", null, 3)]
    [InlineData("1.2{01}", "1.2", null, 3)]
    [InlineData("1.2{0}", "1.2", "0", 6)]
    [InlineData("1.2{10}", "1.2", "10", 7)]
    public static void TryParseNOidLen(string data, string expectedOid, string? expectedLen, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseNOidLen(data, out var actualOid, out var actualLen,
            out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expectedOid, actualOid);
        Assert.Equal(expectedLen, actualLen);
        Assert.Equal(expectedConsumed, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a1")]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("1")]
    [InlineData("1.")]
    public static void TryParseNOidLenFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseNOidLen(data, out var actualOid, out var actualLen,
            out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualOid);
        Assert.Null(actualLen);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("'abc'", "abc", 5)]
    [InlineData("'abc' ", "abc", 5)]
    [InlineData("'abc-123'", "abc-123", 9)]
    [InlineData("'abc-123' ", "abc-123", 9)]
    public static void TryParseQDescr(string data, string expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDescr(data, out var actualqdescr, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualqdescr);
        Assert.Equal(expectedConsumed, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("'")]
    [InlineData("abc")]
    [InlineData("'abc")]
    [InlineData("abc\\'")]
    [InlineData("'1abc'")]
    [InlineData("'-abc'")]
    [InlineData("'abc def'")]
    public static void TryParseQDescrFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDescr(data, out var actualqdescr, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualqdescr);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("'abc'", new[] { "abc" }, 5)]
    [InlineData("'abc' ", new[] { "abc" }, 5)]
    [InlineData("'abc-123'", new[] { "abc-123" }, 9)]
    [InlineData("'abc-123' ", new[] { "abc-123" }, 9)]
    [InlineData("('abc')", new[] { "abc" }, 7)]
    [InlineData("('abc') ", new[] { "abc" }, 7)]
    [InlineData("( 'abc' )", new[] { "abc" }, 9)]
    [InlineData("( 'abc' )  ", new[] { "abc" }, 9)]
    [InlineData("(  'abc'  )", new[] { "abc" }, 11)]
    [InlineData("('abc' 'def1' )", new[] { "abc", "def1" }, 15)]
    public static void TryParseQDescrs(string data, string[] expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDescrs(data, out var actualqdescrs, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualqdescrs);
        Assert.Equal(expectedConsumed, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("'")]
    [InlineData("abc")]
    [InlineData("'abc")]
    [InlineData("abc\\'")]
    [InlineData("'1abc'")]
    [InlineData("'-abc'")]
    [InlineData("'abc def'")]
    [InlineData("(abc)")]
    [InlineData("('abc'")]
    [InlineData("('abc)")]
    [InlineData("('1abc')")]
    [InlineData("( 'abc''def' )")]
    public static void TryParseQDescrsFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDescrs(data, out var actualqdescrs, out var charsConsumed);

        Assert.False(actual);
        Assert.Empty(actualqdescrs);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("'abc'", "abc", 5)]
    [InlineData("'abc' ", "abc", 5)]
    [InlineData("'abc-123'", "abc-123", 9)]
    [InlineData("'abc-123' ", "abc-123", 9)]
    [InlineData("'café'", "café", 6)]
    [InlineData("'café' ", "café", 6)]
    [InlineData("'café \\27'", "café '", 10)]
    [InlineData("'café \\5c\\27'", "café \\'", 13)]
    [InlineData("'café \\5C\\27'", "café \\'", 13)]
    public static void TryParseQDString(string data, string expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDString(data, out var actualqdstring, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualqdstring);
        Assert.Equal(expectedConsumed, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("'")]
    [InlineData("abc")]
    [InlineData("'abc")]
    [InlineData("'abc\\'")]
    public static void TryParseQDStringFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDString(data, out var actualqdstring, out var charsConsumed);

        Assert.False(actual);
        Assert.Equal("", actualqdstring);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData("'abc'", new[] { "abc" }, 5)]
    [InlineData("'abc' ", new[] { "abc" }, 5)]
    [InlineData("'abc-123'", new[] { "abc-123" }, 9)]
    [InlineData("'abc-123' ", new[] { "abc-123" }, 9)]
    [InlineData("('abc')", new[] { "abc" }, 7)]
    [InlineData("('abc') ", new[] { "abc" }, 7)]
    [InlineData("( 'abc' )", new[] { "abc" }, 9)]
    [InlineData("( 'abc' )  ", new[] { "abc" }, 9)]
    [InlineData("(  'abc'  )", new[] { "abc" }, 11)]
    [InlineData("('abc' 'def1' )", new[] { "abc", "def1" }, 15)]
    [InlineData("('café \\5c' '\\5C\\27😊 happy_123\\5c\\27' ) ", new[] { "café \\", "\\'😊 happy_123\\'" }, 40)]
    public static void TryParseQDStrings(string data, string[] expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDStrings(data, out var actualqdstrings, out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, actualqdstrings);
        Assert.Equal(expectedConsumed, charsConsumed);
    }

    [Theory]
    [InlineData("")]
    [InlineData("'")]
    [InlineData("abc")]
    [InlineData("'abc")]
    [InlineData("abc\\'")]
    [InlineData("(abc)")]
    [InlineData("('abc'")]
    [InlineData("('abc\\')")]
    [InlineData("('abc\\27)")]
    [InlineData("('abc)")]
    [InlineData("( 'abc''def' )")]
    public static void TryParseQDStringsFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDStrings(data, out var actualqdstrings, out var charsConsumed);

        Assert.False(actual);
        Assert.Empty(actualqdstrings);
        Assert.Equal(0, charsConsumed);
    }

    [Fact]
    public static void TryParseExtensionsEmpty()
    {
        const string EXTENSIONS_EMPTY = "";

        bool actual = AbnfDecoder.TryParseExtensions(EXTENSIONS_EMPTY, out var extensions,
            out var charsConsumed);

        Assert.True(actual);
        Assert.Empty(extensions);
        Assert.Equal(0, charsConsumed);
    }

    [Fact]
    public static void TryParseExtensions()
    {
        const string EXTENSIONS_RAW = " X-ab 'value' X-def_f  'foo \\27café\\27' X-- ('hello' 'world' ) ";
        Dictionary<string, string[]> expected = new()
        {
            { "X-ab", new[] { "value" } },
            { "X-def_f", new[] { "foo 'café'" } },
            { "X--", new[] { "hello", "world" } },
        };

        bool actual = AbnfDecoder.TryParseExtensions(EXTENSIONS_RAW, out var extensions,
            out var charsConsumed);

        Assert.True(actual);
        Assert.Equal(expected, extensions);
        Assert.Equal(62, charsConsumed);
    }

    [Theory]
    [InlineData(" X 'foo'")]
    [InlineData(" X- 'foo'")]
    [InlineData(" X-123 'foo'")]
    public static void TryParseExtensionsInvalidKey(string data)
    {
        bool actual = AbnfDecoder.TryParseExtensions(data, out var extensions, out var charsConsumed);

        Assert.True(actual);
        Assert.Empty(extensions);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData(" X-foo'bar'")]
    [InlineData(" X-foo( 'bar' )")]
    public static void TryParseExtensionsNoSpace(string data)
    {
        bool actual = AbnfDecoder.TryParseExtensions(data, out var extensions, out var charsConsumed);

        Assert.True(actual);
        Assert.Empty(extensions);
        Assert.Equal(0, charsConsumed);
    }

    [Theory]
    [InlineData(" X-foo cafe")]
    [InlineData(" X-foo 'caf\\'")]
    [InlineData(" X-foo ('caf\\')")]
    [InlineData(" X-foo ('foo'")]
    public static void TryParseExtensionsInvalidValue(string data)
    {
        bool actual = AbnfDecoder.TryParseExtensions(data, out var extensions, out var charsConsumed);

        Assert.True(actual);
        Assert.Empty(extensions);
        Assert.Equal(0, charsConsumed);
    }
}

public static class AbnfEncoderTests
{
    [Theory]
    [InlineData(new string[] { }, "''")]
    [InlineData(new[] { "1.2.3" }, "1.2.3")]
    [InlineData(new[] { "foo", "23.94.0.1" }, "( foo $ 23.94.0.1 )")]
    public static void EncodeOIds(string[] value, string expected)
    {
        string actual = AbnfEncoder.EncodeOids(value);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(new string[] { }, "''")]
    [InlineData(new[] { "abc" }, "'abc'")]
    [InlineData(new[] { "café", "'foo'", "\\bar" }, "( 'café' '\\27foo\\27' '\\5Cbar' )")]
    public static void EncodeQDStrings(string[] value, string expected)
    {
        string actual = AbnfEncoder.EncodeQDStrings(value);

        Assert.Equal(expected, actual);
    }
}
