using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class MatchingRuleDescriptionTests
{
    [Fact]
    public static void ParseMatchingRuleDescription()
    {
        const string VALUE = "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";

        var actual = new MatchingRuleDescription(VALUE);

        Assert.Equal("2.5.13.2", actual.OID);
        Assert.Equal(new[] { "caseIgnoreMatch" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("1.3.6.1.4.1.1466.115.121.1.15", actual.Syntax);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseNoOptional()
    {
        const string VALUE = "( 2.5.13.2 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";

        var actual = new MatchingRuleDescription(VALUE);

        Assert.Equal("2.5.13.2", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("1.3.6.1.4.1.1466.115.121.1.15", actual.Syntax);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "( 1.0 SYNTAX 1.2 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 SYNTAX 1.2 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new MatchingRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("1.2", actual.Syntax);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) SYNTAX 1.2 )";

        var actual = new MatchingRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "name1", "name2" }, actual.Names);

        Assert.Equal("( 1.0 NAME ( 'name1' 'name2' ) SYNTAX 1.2 )", actual.ToString());
    }

    [Fact]
    public static void ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' SYNTAX 1.2 )";

        var actual = new MatchingRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal("foo 'bar'", actual.Description);

        Assert.Equal("( 1.0 DESC 'foo \\27bar\\27' SYNTAX 1.2 )", actual.ToString());
    }

    [Fact]
    public static void ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE SYNTAX 1.2)";

        var actual = new MatchingRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.True(actual.Obsolete);

        Assert.Equal("( 1.0 OBSOLETE SYNTAX 1.2 )", actual.ToString());
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 SYNTAX 1.2 )";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 SYNTAX 1.2 ";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void NoSyntaxValue()
    {
        const string VALUE = "( 1.2 )";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleDescription SYNTAX value is missing", ex.Message);
    }

    [Fact]
    public static void InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure SYNTAX 1.2 )";

        var ex = Assert.Throws<FormatException>(() => new MatchingRuleDescription(VALUE));

        Assert.Equal("Invalid MatchingRuleDescription NAME value is invalid", ex.Message);
    }
}
