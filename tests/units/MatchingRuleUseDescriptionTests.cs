using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class MatchingRuleUseDescriptionTests
{
    [Fact]
    public static void ParseMatchingRuleUseDescription()
    {
        const string VALUE = "( 2.5.13.16 APPLIES ( givenName $ surname ) )";

        var actual = new MatchingRuleUseDescription(VALUE);

        Assert.Equal("2.5.13.16", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal(new [] { "givenName", "surname" }, actual.Applies);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "(  1.0 APPLIES givenName X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 APPLIES givenName X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new MatchingRuleUseDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal(new [] { "givenName" }, actual.Applies);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) APPLIES test )";

        var actual = new MatchingRuleUseDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "name1", "name2" }, actual.Names);

        Assert.Equal("( 1.0 NAME ( 'name1' 'name2' ) APPLIES test )", actual.ToString());
    }

    [Fact]
    public static void ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' APPLIES 1.2 )";

        var actual = new MatchingRuleUseDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal("foo 'bar'", actual.Description);

        Assert.Equal("( 1.0 DESC 'foo \\27bar\\27' APPLIES 1.2 )", actual.ToString());
    }

    [Fact]
    public static void ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE APPLIES 1.2)";

        var actual = new MatchingRuleUseDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.True(actual.Obsolete);

        Assert.Equal("( 1.0 OBSOLETE APPLIES 1.2 )", actual.ToString());
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 APPLIES 1.2 )";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleUseDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleUseDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 APPLIES 1.2 ";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleUseDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleUseDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void NoSyntaxValue()
    {
        const string VALUE = "( 1.2 )";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleUseDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleUseDescription APPLIES value is missing", ex.Message);
    }

    [Fact]
    public static void InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure APPLIES 1.2 )";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleUseDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleUseDescription NAME value is invalid", ex.Message);
    }
}
