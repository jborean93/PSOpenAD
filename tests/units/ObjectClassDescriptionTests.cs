using PSOpenAD.LDAP;
using System;
using System.Collections.Generic;
using Xunit;

namespace PSOpenADTests;

public static class ObjectClassDescriptionTests
{
    [Fact]
    public static void ParseAttributeDescription()
    {
        const string VALUE = "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("2.5.6.2", actual.OID);
        Assert.Equal(new[] { "country" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.Equal(new[] { "top" }, actual.SuperTypes);
        Assert.Equal(ObjectClassKind.Structural, actual.Kind);
        Assert.Equal(new[] { "c" }, actual.Must);
        Assert.Equal(new[] { "searchGuide", "description" }, actual.May);
        Assert.Empty(actual.Extensions);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseAttributeDescriptionAD()
    {
        const string VALUE = "( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST (cn ) MAY (serialNumber $ l $ o $ ou $ owner $ seeAlso $ msSFU30Name $ msSFU30Aliases $ msSFU30NisDomain $ nisMapName ) )";
        const string EXPECTED_STR = "( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST cn MAY ( serialNumber $ l $ o $ ou $ owner $ seeAlso $ msSFU30Name $ msSFU30Aliases $ msSFU30NisDomain $ nisMapName ) )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("2.5.6.14", actual.OID);
        Assert.Equal(new[] { "device" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.Equal(new[] { "top" }, actual.SuperTypes);
        Assert.Equal(ObjectClassKind.Structural, actual.Kind);
        Assert.Equal(new[] { "cn" }, actual.Must);
        Assert.Equal(new[] { "serialNumber", "l", "o", "ou", "owner", "seeAlso", "msSFU30Name", "msSFU30Aliases",
            "msSFU30NisDomain", "nisMapName" }, actual.May);
        Assert.Empty(actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseNoOptional()
    {
        const string VALUE = "( 1.0 )";
        const string EXPECTED_STR = "( 1.0 STRUCTURAL )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.Empty(actual.SuperTypes);
        Assert.Equal(ObjectClassKind.Structural, actual.Kind);
        Assert.Empty(actual.Must);
        Assert.Empty(actual.May);
        Assert.Empty(actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithExtensions()
    {
        const string VALUE = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 STRUCTURAL X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Empty(actual.Names);
        Assert.Null(actual.Description);
        Assert.Empty(actual.SuperTypes);
        Assert.Equal(ObjectClassKind.Structural, actual.Kind);
        Assert.Empty(actual.Must);
        Assert.Empty(actual.May);
        Assert.Equal(expectedExtensions, actual.Extensions);

        Assert.Equal(EXPECTED_STR, actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "name1", "name2" }, actual.Names);

        Assert.Equal("( 1.0 NAME ( 'name1' 'name2' ) STRUCTURAL )", actual.ToString());
    }

    [Fact]
    public static void ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal("foo 'bar'", actual.Description);

        Assert.Equal("( 1.0 DESC 'foo \\27bar\\27' STRUCTURAL )", actual.ToString());
    }

    [Fact]
    public static void ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.True(actual.Obsolete);

        Assert.Equal("( 1.0 OBSOLETE STRUCTURAL )", actual.ToString());
    }

    [Fact]
    public static void ParseWithOneSuperType()
    {
        const string VALUE = "(1.0  SUP 1.2.3.4 )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "1.2.3.4" }, actual.SuperTypes);

        Assert.Equal("( 1.0 SUP 1.2.3.4 STRUCTURAL )", actual.ToString());
    }

    [Fact]
    public static void ParseWithMultipleSuperType()
    {
        const string VALUE = "(1.0  SUP (name$1.10.3845 $other ) )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(new[] { "name", "1.10.3845", "other" }, actual.SuperTypes);

        Assert.Equal("( 1.0 SUP ( name $ 1.10.3845 $ other ) STRUCTURAL )", actual.ToString());
    }

    [Fact]
    public static void ParseAbstractKind()
    {
        const string VALUE = "( 1.0 ABSTRACT )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(ObjectClassKind.Abstract, actual.Kind);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ParseAuxiliaryKind()
    {
        const string VALUE = "( 1.0 AUXILIARY )";

        var actual = new ObjectClassDescription(VALUE);

        Assert.Equal("1.0", actual.OID);
        Assert.Equal(ObjectClassKind.Auxiliary, actual.Kind);

        Assert.Equal(VALUE, actual.ToString());
    }

    [Fact]
    public static void ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = Assert.Throws<FormatException>(() => new ObjectClassDescription(VALUE));

        Assert.Equal("Invalid ObjectClassDescription value does not start with '('", ex.Message);
    }

    [Fact]
    public static void ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = Assert.Throws<FormatException>(() => new ObjectClassDescription(VALUE));

        Assert.Equal("Invalid ObjectClassDescription value does not end with ')'", ex.Message);
    }

    [Fact]
    public static void NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = Assert.Throws<FormatException>(() => new ObjectClassDescription(VALUE));

        Assert.Equal("Invalid ObjectClassDescription OID value is invalid", ex.Message);
    }

    [Fact]
    public static void InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure )";

        var ex = Assert.Throws<FormatException>(() => new ObjectClassDescription(VALUE));

        Assert.Equal("Invalid ObjectClassDescription NAME value is invalid", ex.Message);
    }
}
