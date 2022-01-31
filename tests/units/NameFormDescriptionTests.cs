using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class NameFormDescriptionTests
{
    [Fact]
    public static void ParseNameFormDescription()
    {
        const string VALUE = "( 2.5.15.3 NAME 'orgNameForm' OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        Assert.Equal("2.5.15.3", actual.OID);
        Assert.Equal(new[] { "orgNameForm" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("organization", actual.ObjectClass);
        Assert.Equal(new[] { "o" }, actual.Must);
        Assert.Empty(actual.May);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseNoOptional()
    {
        const string VALUE = "( 2.5.15.3 OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        Assert.Equal("2.5.15.3", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("organization", actual.ObjectClass);
        Assert.Equal(new[] { "o" }, actual.Must);
        Assert.Empty(actual.May);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "( 2.5.15.3 OC organization MUST o X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 2.5.15.3 OC organization MUST o X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new NameFormDescription(VALUE);

        Assert.Equal("2.5.15.3", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("organization", actual.ObjectClass);
        Assert.Equal(new[] { "o" }, actual.Must);
        Assert.Empty(actual.May);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) OC 10.3 MUST (o$3.0.1) )";

        var actual = new NameFormDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "name1", "name2" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Equal("10.3", actual.ObjectClass);
        Assert.Equal(new[] { "o", "3.0.1" }, actual.Must);
        Assert.Empty(actual.May);
        Assert.Empty(actual.Extensions);

        Assert.Equal("( 1.0 NAME ( 'name1' 'name2' ) OC 10.3 MUST ( o $ 3.0.1 ) )", actual.ToString());
    }

    [Fact]
    public static void ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal("foo 'bar'", actual.Description);

        Assert.Equal("( 1.0 DESC 'foo \\27bar\\27' OC organization MUST o )", actual.ToString());
    }

    [Fact]
    public static void ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.True(actual.Obsolete);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithMay()
    {
        const string VALUE = "( 1.0 OC organization MUST o MAY (abc$ def$134.0 ))";

        var actual = new NameFormDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "abc", "def", "134.0" }, actual.May);

        Assert.Equal("( 1.0 OC organization MUST o MAY ( abc $ def $ 134.0 ) )", actual.ToString());
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = Assert.Throws<FormatException>(() => new NameFormDescription(VALUE));

        Assert.Equal("Invalid NameFormDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void NoOCValue()
    {
        const string VALUE = "( 1.0 MUST o )";

        var ex = Assert.Throws<FormatException>(() => new NameFormDescription(VALUE));

        Assert.Equal("Invalid NameFormDescription OC value is missing", ex.Message);
    }

    [Fact]
    public static void NoMustValue()
    {
        const string VALUE = "( 1.0 OC o )";

        var ex = Assert.Throws<FormatException>(() => new NameFormDescription(VALUE));

        Assert.Equal("Invalid NameFormDescription MUST value is missing", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 OC test MUST abc ";

        var ex = Assert.Throws<FormatException>(() => new NameFormDescription(VALUE));

        Assert.Equal("Invalid NameFormDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = Assert.Throws<FormatException>(() => new NameFormDescription(VALUE));

        Assert.Equal("Invalid NameFormDescription OID value is invalid", ex.Message);
    }

    [Fact]
    public static void InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure )";

        var ex = Assert.Throws<FormatException>(() => new NameFormDescription(VALUE));

        Assert.Equal("Invalid NameFormDescription NAME value is invalid", ex.Message);
    }
}
