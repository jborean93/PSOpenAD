using PSOpenAD.LDAP;
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
}
