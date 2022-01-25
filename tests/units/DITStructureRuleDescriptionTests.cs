using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class DITStructureRuleDescriptionTests
{
    [Fact]
    public static void ParseDITStructureRuleDescription()
    {
        const string VALUE = "( 2 DESC 'organization structure rule' FORM 2.5.15.3 )";

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("2", actual.Id);
        Assert.Empty(actual.Names);
        Assert.Equal("organization structure rule", actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("2.5.15.3", actual.Form);
        Assert.Empty(actual.SuperRules);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseNoOptional()
    {
        const string VALUE = "( 0 FORM 2.0 )";

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("0", actual.Id);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("2.0", actual.Form);
        Assert.Empty(actual.SuperRules);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "( 1 FORM 2.1 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1 FORM 2.1 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("1", actual.Id);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("2.1", actual.Form);
        Assert.Empty(actual.SuperRules);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleNames()
    {
        const string VALUE = "(9  NAME ('name1' 'name2' ) FORM 2.1010.98)";

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("9", actual.Id);
        Assert.Equal(new[] { "name1", "name2" }, actual.Names);
        Assert.Equal("2.1010.98", actual.Form);

        Assert.Equal("( 9 NAME ( 'name1' 'name2' ) FORM 2.1010.98 )", actual.ToString());
    }

    [Fact]
    public static void ParseWithDescription()
    {
        const string VALUE = "( 9 DESC 'testing 123' FORM 2.1010.98 )";

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("9", actual.Id);
        Assert.Equal("testing 123", actual.Description);
        Assert.Equal("2.1010.98", actual.Form);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithObsolete()
    {
        const string VALUE = "( 272 OBSOLETE FORM 10.0)";

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("272", actual.Id);
        Assert.True(actual.Obsolete);

        Assert.Equal("( 272 OBSOLETE FORM 10.0 )", actual.ToString());
    }

    [Fact]
    public static void ParseWithSingleSupRule()
    {
        const string VALUE = "( 1 FORM 2.3 SUP 12039 )";

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("1", actual.Id);
        Assert.Equal("2.3", actual.Form);
        Assert.Equal(new[] { "12039" }, actual.SuperRules);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleSupRules()
    {
        const string VALUE = "( 1 FORM 2.3 SUP ( 12039 351835 ) )";

        var actual = new DITStructureRuleDescription(VALUE);

        Assert.Equal("1", actual.Id);
        Assert.Equal("2.3", actual.Form);
        Assert.Equal(new[] { "12039", "351835" }, actual.SuperRules);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1 FORM 2.3 )";

        var ex = Assert.Throws<FormatException>(() => new DITStructureRuleDescription(VALUE));

        Assert.Equal("Invalid DITStructureRuleDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1 FORM 2.3";

        var ex = Assert.Throws<FormatException>(() => new DITStructureRuleDescription(VALUE));

        Assert.Equal("Invalid DITStructureRuleDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void NoIDValue()
    {
        const string VALUE = "( FORM 2.3 )";

        var ex = Assert.Throws<FormatException>(() => new DITStructureRuleDescription(VALUE));

        Assert.Equal("Invalid DITStructureRuleDescription ID value is invalid", ex.Message);
    }

    [Fact]
    public static void InvalidFieldValue()
    {
        const string VALUE = "( 1 FORM 2.3 SUP-1234 )";

        var ex = Assert.Throws<FormatException>(() => new DITStructureRuleDescription(VALUE));

        Assert.Equal("Invalid DITStructureRuleDescription SUP value is invalid", ex.Message);
    }
}
