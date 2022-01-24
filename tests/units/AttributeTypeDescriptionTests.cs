using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class AttributeTypeDescriptionTests
{
    [Fact]
    public static void ParseAttributeDescription()
    {
        const string VALUE = "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("2.5.18.1", actual.OID);
        Assert.Equal(new[] { "createTimestamp" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Null(actual.SuperType);
        Assert.Equal("generalizedTimeMatch", actual.Equality);
        Assert.Equal("generalizedTimeOrderingMatch", actual.Ordering);
        Assert.Null(actual.Substrings);
        Assert.Equal("1.3.6.1.4.1.1466.115.121.1.24", actual.Syntax);
        Assert.Null(actual.SyntaxLength);
        Assert.True(actual.SingleValue);
        Assert.False(actual.Collective);
        Assert.True(actual.NoUserModification);
        Assert.Equal(AttributeTypeUsage.DirectoryOperation, actual.Usage);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 1274' )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
        };

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("0.9.2342.19200300.100.1.1", actual.OID);
        Assert.Equal(new[] { "uid" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Null(actual.SuperType);
        Assert.Equal("caseIgnoreMatch", actual.Equality);
        Assert.Null(actual.Ordering);
        Assert.Equal("caseIgnoreSubstringsMatch", actual.Substrings);
        Assert.Equal("1.3.6.1.4.1.1466.115.121.1.15", actual.Syntax);
        Assert.Equal(256, actual.SyntaxLength);
        Assert.False(actual.SingleValue);
        Assert.False(actual.Collective);
        Assert.False(actual.NoUserModification);
        Assert.Equal(AttributeTypeUsage.UserApplications, actual.Usage);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseADSyntaxOID()
    {
        const string VALUE = "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )";
        const string EXPECTED_STR = "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.2.840.113556.1.4.221", actual.OID);
        Assert.Equal(new[] { "sAMAccountName" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Null(actual.SuperType);
        Assert.Null(actual.Equality);
        Assert.Null(actual.Ordering);
        Assert.Null(actual.Substrings);
        Assert.Equal("1.3.6.1.4.1.1466.115.121.1.15", actual.Syntax);
        Assert.Null(actual.SyntaxLength);
        Assert.True(actual.SingleValue);
        Assert.False(actual.Collective);
        Assert.False(actual.NoUserModification);
        Assert.Equal(AttributeTypeUsage.UserApplications, actual.Usage);
        Assert.Empty(actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseADSyntaxDesc()
    {
        const string VALUE = "( 1.2.840.113556.1.2.83 NAME 'repsTo' SYNTAX 'OctetString' NO-USER-MODIFICATION )";
        const string EXPECTED_STR = "( 1.2.840.113556.1.2.83 NAME 'repsTo' SYNTAX OctetString NO-USER-MODIFICATION )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.2.840.113556.1.2.83", actual.OID);
        Assert.Equal(new[] { "repsTo" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Null(actual.SuperType);
        Assert.Null(actual.Equality);
        Assert.Null(actual.Ordering);
        Assert.Null(actual.Substrings);
        Assert.Equal("OctetString", actual.Syntax);
        Assert.Null(actual.SyntaxLength);
        Assert.False(actual.SingleValue);
        Assert.False(actual.Collective);
        Assert.True(actual.NoUserModification);
        Assert.Equal(AttributeTypeUsage.UserApplications, actual.Usage);
        Assert.Empty(actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithNonames()
    {
        const string VALUE = "( 1.0 )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Empty(actual.Names);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "name1", "name2" }, actual.Names);

        Assert.Equal("( 1.0 NAME ( 'name1' 'name2' ) )", actual.ToString());
    }

    [Fact]
    public static void ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal("foo 'bar'", actual.Description);

        Assert.Equal("( 1.0 DESC 'foo \\27bar\\27' )", actual.ToString());
    }

    [Fact]
    public static void ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.True(actual.Obsolete);

        Assert.Equal("( 1.0 OBSOLETE )", actual.ToString());
    }

    [Fact]
    public static void ParseWithSuperType()
    {
        const string VALUE = "( 1.0 SUP 1.2.34  )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal("1.2.34", actual.SuperType);

        Assert.Equal("( 1.0 SUP 1.2.34 )", actual.ToString());
    }

    [Fact]
    public static void ParseWithCollective()
    {
        const string VALUE = "( 1.0 COLLECTIVE   )";

        var actual = new AttributeTypeDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.True(actual.Collective);

        Assert.Equal("( 1.0 COLLECTIVE )", actual.ToString());
    }

    [Theory]
    [InlineData("userApplications", AttributeTypeUsage.UserApplications)]
    [InlineData("directoryOperation", AttributeTypeUsage.DirectoryOperation)]
    [InlineData("distributedOperation", AttributeTypeUsage.DistributedOperation)]
    [InlineData("dSAOperation", AttributeTypeUsage.DsaOperation)]
    public static void ParseWithUsage(string usage, AttributeTypeUsage expected)
    {
        string value = $"( 1.0 USAGE {usage} )";

        var actual = new AttributeTypeDescription(value);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(expected, actual.Usage);

        if (usage == "userApplications")
        {
            Assert.Equal("( 1.0 )", actual.ToString());
        }
        else
        {
            Assert.Equal($"( 1.0 USAGE {usage} )", actual.ToString());
        }
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = Assert.Throws<FormatException>(() => new AttributeTypeDescription(VALUE));

        Assert.Equal("Invalid AttributeTypeDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = Assert.Throws<FormatException>(() => new AttributeTypeDescription(VALUE));

        Assert.Equal("Invalid AttributeTypeDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = Assert.Throws<FormatException>(() => new AttributeTypeDescription(VALUE));

        Assert.Equal("Invalid AttributeTypeDescription value has no numericoid value", ex.Message);
    }

    [Fact]
    public static void UsageWithInvalidValue()
    {
        const string VALUE = "( 1.0 USAGE invalidValue )";

        var ex = Assert.Throws<FormatException>(() => new AttributeTypeDescription(VALUE));

        Assert.Equal("Invalid AttributeTypeDescription USAGE value is invalid", ex.Message);
    }
}
