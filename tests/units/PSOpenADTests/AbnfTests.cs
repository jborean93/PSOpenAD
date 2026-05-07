using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class AbnfDecoderTests
{
    [Test]
    [Arguments(" ", " ")]
    [Arguments("  ", "  ")]
    [Arguments(" testing", " ")]
    [Arguments("    abc def", "    ")]
    public async Task TryParseSP(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseSP(data, out var actualSP, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualSP).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expected.Length);
    }

    [Test]
    [Arguments("")]
    [Arguments("a ")]
    public async Task TryParseSPFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseSP(data, out var actualSP, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualSP).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments(" ", " ")]
    [Arguments("  ", "  ")]
    [Arguments(" testing", " ")]
    [Arguments("    abc def", "    ")]
    [Arguments("", "")]
    [Arguments("a ", "")]
    public async Task TryParseWSP(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseWSP(data, out var actualSP, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualSP).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expected.Length);
    }

    [Test]
    [Arguments("a", "a")]
    [Arguments("a ", "a")]
    [Arguments("abc", "abc")]
    [Arguments("abc ", "abc")]
    [Arguments("ABC", "ABC")]
    [Arguments("ABC ", "ABC")]
    [Arguments("a123", "a123")]
    [Arguments("a-123-", "a-123-")]
    [Arguments("a-123-_ ", "a-123-")]
    [Arguments("A23 ", "A23")]
    [Arguments("café ", "caf")]
    public async Task TryParseKeyString(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseKeyString(data, out var actualKS, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualKS).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expected.Length);
    }

    [Test]
    [Arguments(" abc")]
    [Arguments("1abc")]
    [Arguments("-abc")]
    [Arguments("0")]
    [Arguments("-")]
    [Arguments("ést")]
    public async Task TryParseKeyStringFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseKeyString(data, out var actualSP, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualSP).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("a", "a", 1)]
    [Arguments("a ", "a ", 2)]
    [Arguments("abc", "abc", 3)]
    [Arguments("abc ", "abc ", 4)]
    [Arguments("abc\\ ", "abc", 3)]
    [Arguments("abc' ", "abc", 3)]
    [Arguments("ABC", "ABC", 3)]
    [Arguments("ABC ", "ABC ", 4)]
    [Arguments("a123", "a123", 4)]
    [Arguments("a-123-", "a-123-", 6)]
    [Arguments("a-123-_ ", "a-123-_ ", 8)]
    [Arguments("A23 ", "A23 ", 4)]
    [Arguments("café ", "café ", 5)]
    [Arguments("testing\\5", "testing", 7)]
    [Arguments("testing\\5' ", "testing", 7)]
    [Arguments("testing\\5c", "testing\\", 10)]
    [Arguments("testing\\5c' abc", "testing\\", 10)]
    [Arguments("testing\\27 abc\\5c\\27 ' ", "testing' abc\\' ", 21)]
    public async Task TryParseEscapedUTF8String(string data, string expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseEscapedUTF8String(data, out var actualKS, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualKS).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
    }

    [Test]
    [Arguments("")]
    [Arguments("'")]
    [Arguments("\\")]
    public async Task TryParseEscapedUTF8StringFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseEscapedUTF8String(data, out var actualSP, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualSP).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("0", "0")]
    [Arguments("01", "0")]
    [Arguments("1", "1")]
    [Arguments("10", "10")]
    [Arguments("101 01", "101")]
    [Arguments("101a", "101")]
    public async Task TryParseNumber(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseNumber(data, out var actualNumber, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualNumber).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expected.Length);
    }

    [Test]
    [Arguments("")]
    [Arguments("a1")]
    public async Task TryParseNumberFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseNumber(data, out var actualNumber, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualNumber).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("0.0", "0.0")]
    [Arguments("1.0", "1.0")]
    [Arguments("1.01", "1.0")]
    [Arguments("1.1", "1.1")]
    [Arguments("1.1 ", "1.1")]
    [Arguments("1.1.", "1.1")]
    [Arguments("1.1.a", "1.1")]
    [Arguments("1.1. ", "1.1")]
    [Arguments("70978.0", "70978.0")]
    [Arguments("112.325423.0.91.12.932", "112.325423.0.91.12.932")]
    public async Task TryParseNumericOid(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseNumericOid(data, out var actualNumericOid, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualNumericOid).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expected.Length);
    }

    [Test]
    [Arguments("")]
    [Arguments("a1")]
    [Arguments("0")]
    [Arguments("01")]
    [Arguments("1")]
    [Arguments("1.")]
    public async Task TryParseNumericOidFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseNumericOid(data, out var actualNumericOid, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualNumericOid).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("1.0", new[] { "1.0" }, 3)]
    [Arguments("( 1.29.1 )", new[] { "1.29.1" }, 10)]
    [Arguments("(  1.29.1 )", new[] { "1.29.1" }, 11)]
    [Arguments("( 1.29.1  )", new[] { "1.29.1" }, 11)]
    [Arguments("(  1.29.1  )", new[] { "1.29.1" }, 12)]
    [Arguments("(3.85$129.3.0)", new[] { "3.85", "129.3.0" }, 14)]
    [Arguments("( 3.85$129.3.0)", new[] { "3.85", "129.3.0" }, 15)]
    [Arguments("(3.85$129.3.0  )", new[] { "3.85", "129.3.0" }, 16)]
    [Arguments("(3.85   $129.3.0)", new[] { "3.85", "129.3.0" }, 17)]
    [Arguments("(3.85$ 129.3.0)", new[] { "3.85", "129.3.0" }, 15)]
    public async Task TryParseOids(string data, string[] expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseOids(data, out var actualOids, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualOids).IsEquivalentTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
    }

    [Test]
    [Arguments("")]
    [Arguments("01")]
    [Arguments("1")]
    [Arguments("1.")]
    [Arguments("(1.2 | 3.4)")]
    [Arguments("(1.2 $ -abc)")]
    public async Task TryParseOidsFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseOids(data, out var actualOids, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualOids.Length).IsEqualTo(0);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("0.0", "0.0")]
    [Arguments("1.0", "1.0")]
    [Arguments("1.01", "1.0")]
    [Arguments("1.1", "1.1")]
    [Arguments("1.1 ", "1.1")]
    [Arguments("1.1.", "1.1")]
    [Arguments("1.1.a", "1.1")]
    [Arguments("1.1. ", "1.1")]
    [Arguments("70978.0", "70978.0")]
    [Arguments("112.325423.0.91.12.932", "112.325423.0.91.12.932")]
    [Arguments("a", "a")]
    [Arguments("a ", "a")]
    [Arguments("abc", "abc")]
    [Arguments("abc ", "abc")]
    [Arguments("ABC", "ABC")]
    [Arguments("ABC ", "ABC")]
    [Arguments("a123", "a123")]
    [Arguments("a-123-", "a-123-")]
    [Arguments("a-123-_ ", "a-123-")]
    [Arguments("A23 ", "A23")]
    [Arguments("café ", "caf")]
    public async Task TryParseOid(string data, string expected)
    {
        bool actual = AbnfDecoder.TryParseOid(data, out var actualOid, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualOid).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expected.Length);
    }

    [Test]
    [Arguments("")]
    [Arguments("0")]
    [Arguments("01")]
    [Arguments("1")]
    [Arguments("1.")]
    [Arguments(" abc")]
    [Arguments("1abc")]
    [Arguments("-abc")]
    [Arguments("-")]
    [Arguments("ést")]
    public async Task TryParseOidFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseOid(data, out var actualNumericOid, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualNumericOid).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("1.2", "1.2", null, 3)]
    [Arguments("1.2{", "1.2", null, 3)]
    [Arguments("1.2{0", "1.2", null, 3)]
    [Arguments("1.2{}", "1.2", null, 3)]
    [Arguments("1.2{01}", "1.2", null, 3)]
    [Arguments("1.2{0}", "1.2", "0", 6)]
    [Arguments("1.2{10}", "1.2", "10", 7)]
    public async Task TryParseNOidLen(string data, string expectedOid, string? expectedLen, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseNOidLen(data, out var actualOid, out var actualLen,
            out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualOid).IsEqualTo(expectedOid);
        await Assert.That(actualLen).IsEqualTo(expectedLen);
        await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
    }

    [Test]
    [Arguments("")]
    [Arguments("a1")]
    [Arguments("0")]
    [Arguments("01")]
    [Arguments("1")]
    [Arguments("1.")]
    public async Task TryParseNOidLenFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseNOidLen(data, out var actualOid, out var actualLen,
            out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualOid).IsEqualTo("");
        Assert.Null(actualLen);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("'abc'", "abc", 5)]
    [Arguments("'abc' ", "abc", 5)]
    [Arguments("'abc-123'", "abc-123", 9)]
    [Arguments("'abc-123' ", "abc-123", 9)]
    public async Task TryParseQDescr(string data, string expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDescr(data, out var actualqdescr, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualqdescr).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
    }

    [Test]
    [Arguments("")]
    [Arguments("'")]
    [Arguments("abc")]
    [Arguments("'abc")]
    [Arguments("abc\\'")]
    [Arguments("'1abc'")]
    [Arguments("'-abc'")]
    [Arguments("'abc def'")]
    public async Task TryParseQDescrFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDescr(data, out var actualqdescr, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualqdescr).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("'abc'", new[] { "abc" }, 5)]
    [Arguments("'abc' ", new[] { "abc" }, 5)]
    [Arguments("'abc-123'", new[] { "abc-123" }, 9)]
    [Arguments("'abc-123' ", new[] { "abc-123" }, 9)]
    [Arguments("('abc')", new[] { "abc" }, 7)]
    [Arguments("('abc') ", new[] { "abc" }, 7)]
    [Arguments("( 'abc' )", new[] { "abc" }, 9)]
    [Arguments("( 'abc' )  ", new[] { "abc" }, 9)]
    [Arguments("(  'abc'  )", new[] { "abc" }, 11)]
    [Arguments("('abc' 'def1' )", new[] { "abc", "def1" }, 15)]
    public async Task TryParseQDescrs(string data, string[] expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDescrs(data, out var actualqdescrs, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualqdescrs).IsEquivalentTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
    }

    [Test]
    [Arguments("")]
    [Arguments("'")]
    [Arguments("abc")]
    [Arguments("'abc")]
    [Arguments("abc\\'")]
    [Arguments("'1abc'")]
    [Arguments("'-abc'")]
    [Arguments("'abc def'")]
    [Arguments("(abc)")]
    [Arguments("('abc'")]
    [Arguments("('abc)")]
    [Arguments("('1abc')")]
    [Arguments("( 'abc''def' )")]
    public async Task TryParseQDescrsFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDescrs(data, out var actualqdescrs, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualqdescrs.Length).IsEqualTo(0);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("'abc'", "abc", 5)]
    [Arguments("'abc' ", "abc", 5)]
    [Arguments("'abc-123'", "abc-123", 9)]
    [Arguments("'abc-123' ", "abc-123", 9)]
    [Arguments("'café'", "café", 6)]
    [Arguments("'café' ", "café", 6)]
    [Arguments("'café \\27'", "café '", 10)]
    [Arguments("'café \\5c\\27'", "café \\'", 13)]
    [Arguments("'café \\5C\\27'", "café \\'", 13)]
    public async Task TryParseQDString(string data, string expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDString(data, out var actualqdstring, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualqdstring).IsEqualTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
    }

    [Test]
    [Arguments("")]
    [Arguments("'")]
    [Arguments("abc")]
    [Arguments("'abc")]
    [Arguments("'abc\\'")]
    public async Task TryParseQDStringFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDString(data, out var actualqdstring, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualqdstring).IsEqualTo("");
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments("'abc'", new[] { "abc" }, 5)]
    [Arguments("'abc' ", new[] { "abc" }, 5)]
    [Arguments("'abc-123'", new[] { "abc-123" }, 9)]
    [Arguments("'abc-123' ", new[] { "abc-123" }, 9)]
    [Arguments("('abc')", new[] { "abc" }, 7)]
    [Arguments("('abc') ", new[] { "abc" }, 7)]
    [Arguments("( 'abc' )", new[] { "abc" }, 9)]
    [Arguments("( 'abc' )  ", new[] { "abc" }, 9)]
    [Arguments("(  'abc'  )", new[] { "abc" }, 11)]
    [Arguments("('abc' 'def1' )", new[] { "abc", "def1" }, 15)]
    [Arguments("('café \\5c' '\\5C\\27😊 happy_123\\5c\\27' ) ", new[] { "café \\", "\\'😊 happy_123\\'" }, 40)]
    public async Task TryParseQDStrings(string data, string[] expected, int expectedConsumed)
    {
        bool actual = AbnfDecoder.TryParseQDStrings(data, out var actualqdstrings, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(actualqdstrings).IsEquivalentTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(expectedConsumed);
    }

    [Test]
    [Arguments("")]
    [Arguments("'")]
    [Arguments("abc")]
    [Arguments("'abc")]
    [Arguments("abc\\'")]
    [Arguments("(abc)")]
    [Arguments("('abc'")]
    [Arguments("('abc\\')")]
    [Arguments("('abc\\27)")]
    [Arguments("('abc)")]
    [Arguments("( 'abc''def' )")]
    public async Task TryParseQDStringsFailure(string data)
    {
        bool actual = AbnfDecoder.TryParseQDStrings(data, out var actualqdstrings, out var charsConsumed);

        await Assert.That(actual).IsFalse();
        await Assert.That(actualqdstrings.Length).IsEqualTo(0);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    public async Task TryParseExtensionsEmpty()
    {
        const string EXTENSIONS_EMPTY = "";

        bool actual = AbnfDecoder.TryParseExtensions(EXTENSIONS_EMPTY, out var extensions,
            out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(extensions.Count).IsEqualTo(0);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    public async Task TryParseExtensions()
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

        await Assert.That(actual).IsTrue();
        await Assert.That(extensions).IsEquivalentTo(expected);
        await Assert.That(charsConsumed).IsEqualTo(62);
    }

    [Test]
    [Arguments(" X 'foo'")]
    [Arguments(" X- 'foo'")]
    [Arguments(" X-123 'foo'")]
    public async Task TryParseExtensionsInvalidKey(string data)
    {
        bool actual = AbnfDecoder.TryParseExtensions(data, out var extensions, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(extensions.Count).IsEqualTo(0);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments(" X-foo'bar'")]
    [Arguments(" X-foo( 'bar' )")]
    public async Task TryParseExtensionsNoSpace(string data)
    {
        bool actual = AbnfDecoder.TryParseExtensions(data, out var extensions, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(extensions.Count).IsEqualTo(0);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }

    [Test]
    [Arguments(" X-foo cafe")]
    [Arguments(" X-foo 'caf\\'")]
    [Arguments(" X-foo ('caf\\')")]
    [Arguments(" X-foo ('foo'")]
    public async Task TryParseExtensionsInvalidValue(string data)
    {
        bool actual = AbnfDecoder.TryParseExtensions(data, out var extensions, out var charsConsumed);

        await Assert.That(actual).IsTrue();
        await Assert.That(extensions.Count).IsEqualTo(0);
        await Assert.That(charsConsumed).IsEqualTo(0);
    }
}

public class AbnfEncoderTests
{
    [Test]
    [Arguments(new string[] { }, "''")]
    [Arguments(new[] { "1.2.3" }, "1.2.3")]
    [Arguments(new[] { "foo", "23.94.0.1" }, "( foo $ 23.94.0.1 )")]
    public async Task EncodeOIds(string[] value, string expected)
    {
        string actual = AbnfEncoder.EncodeOids(value);

        await Assert.That(actual).IsEqualTo(expected);
    }

    [Test]
    [Arguments(new string[] { }, "''")]
    [Arguments(new[] { "abc" }, "'abc'")]
    [Arguments(new[] { "café", "'foo'", "\\bar" }, "( 'café' '\\27foo\\27' '\\5Cbar' )")]
    public async Task EncodeQDStrings(string[] value, string expected)
    {
        string actual = AbnfEncoder.EncodeQDStrings(value);

        await Assert.That(actual).IsEqualTo(expected);
    }
}
