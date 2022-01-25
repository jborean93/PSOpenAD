using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class DITContentRuleDescriptionTests
{
    [Fact]
    public static void ParseDITContentRuleDescription()
    {
        const string VALUE = "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )";

        var actual = new DITContentRuleDescription(VALUE);

        Assert.Equal("2.5.6.4", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Equal("content rule for organization", actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Empty(actual.Auxiliary);
        Assert.Empty(actual.Must);
        Assert.Empty(actual.May);
        Assert.Equal(new[] { "x121Address", "telexNumber" }, actual.Not);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseDITContentRuleDescriptionAD()
    {
        const string VALUE = "( 1.2.840.113556.1.5.282 NAME 'msDS-GroupManagedServiceAccount' AUX ( mailRecipient $ posixGroup $ ipHost ) MUST (objectSid $ sAMAccountName ) MAY (info $ garbageCollPeriod$ msExchAssistantName ))";
        const string EXPECTED_STR = "( 1.2.840.113556.1.5.282 NAME 'msDS-GroupManagedServiceAccount' AUX ( mailRecipient $ posixGroup $ ipHost ) MUST ( objectSid $ sAMAccountName ) MAY ( info $ garbageCollPeriod $ msExchAssistantName ) )";

        var actual = new DITContentRuleDescription(VALUE);

        Assert.Equal("1.2.840.113556.1.5.282", actual.OID);
        Assert.Equal(new[] { "msDS-GroupManagedServiceAccount" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal(new[] { "mailRecipient", "posixGroup", "ipHost" }, actual.Auxiliary);
        Assert.Equal(new[] { "objectSid", "sAMAccountName" }, actual.Must);
        Assert.Equal(new[] { "info", "garbageCollPeriod", "msExchAssistantName" }, actual.May);
        Assert.Empty(actual.Not);
        Assert.Empty(actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseNoOptional()
    {
        const string VALUE = "( 1.0 )";

        var actual = new DITContentRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Empty(actual.Auxiliary);
        Assert.Empty(actual.Must);
        Assert.Empty(actual.May);
        Assert.Empty(actual.Not);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new DITContentRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Empty(actual.Auxiliary);
        Assert.Empty(actual.Must);
        Assert.Empty(actual.May);
        Assert.Empty(actual.Not);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) )";

        var actual = new DITContentRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "name1", "name2" }, actual.Names);

        Assert.Equal("( 1.0 NAME ( 'name1' 'name2' ) )", actual.ToString());
    }

    [Fact]
    public static void ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE )";

        var actual = new DITContentRuleDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.True(actual.Obsolete);

        Assert.Equal("( 1.0 OBSOLETE )", actual.ToString());
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = Assert.Throws<FormatException>(() => new DITContentRuleDescription(VALUE));

        Assert.Equal("Invalid DITContentRuleDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = Assert.Throws<FormatException>(() => new DITContentRuleDescription(VALUE));

        Assert.Equal("Invalid DITContentRuleDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = Assert.Throws<FormatException>(() => new DITContentRuleDescription(VALUE));

        Assert.Equal("Invalid DITContentRuleDescription OID value is invalid", ex.Message);
    }

    [Fact]
    public static void InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure )";

        var ex = Assert.Throws<FormatException>(() => new DITContentRuleDescription(VALUE));

        Assert.Equal("Invalid DITContentRuleDescription NAME value is invalid", ex.Message);
    }
}
