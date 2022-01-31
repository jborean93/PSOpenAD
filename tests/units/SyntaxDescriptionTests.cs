using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class SyntaxDescriptionTests
{
    [Fact]
    public static void ParseSyntaxDescription()
    {
        const string VALUE = "( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )";

        var actual = new SyntaxDescription(VALUE);

        Assert.Equal("1.3.6.1.4.1.1466.115.121.1.54", actual.OID);
        Assert.Equal("LDAP Syntax Description", actual.Description);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "(  1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new SyntaxDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Null(actual.Description);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = Assert.Throws<FormatException>(() => new SyntaxDescription(VALUE));

        Assert.Equal("Invalid SyntaxDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = Assert.Throws<FormatException>(() => new SyntaxDescription(VALUE));

        Assert.Equal("Invalid SyntaxDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void InvlaidOIDValue()
    {
        const string VALUE = "( 'abc' )";

        var ex = Assert.Throws<FormatException>(() => new SyntaxDescription(VALUE));

        Assert.Equal("Invalid SyntaxDescription OID value is invalid", ex.Message);
    }
}
