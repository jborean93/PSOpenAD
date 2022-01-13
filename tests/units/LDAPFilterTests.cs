using PSOpenAD.LDAP;
using System.Text;
using Xunit;

namespace PSOpenADTests;

public class LDAPFilterEqualityTests
{
    [Fact]
    public void SimpleValue()
    {
        LDAPFilter actual = LDAPFilter.ParseFilter("objectClass=user");

        Assert.IsType<FilterEquality>(actual);
    }
}

public class LDAPFiltrPresentTests
{
    [Theory]
    [InlineData("objectClass", false)]
    [InlineData("objectClass", true)]
    [InlineData("1.2.3.4.12912", false)]
    [InlineData("1.2.3.4.12912", true)]
    public void PresentFilter(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }
}

public class LDAPFilterAttributeTests
{
    [Theory]
    [InlineData("objectClass", false)]
    [InlineData("objectClass", true)]
    [InlineData("sAMAccountName", false)]
    [InlineData("sAMAccountName", true)]
    [InlineData("Test-attr", false)]
    [InlineData("Test-attr", true)]
    [InlineData("test-", false)]
    [InlineData("test-", true)]
    [InlineData("test0", false)]
    [InlineData("test1", true)]
    public void AttributeAsString(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }

    [Theory]
    [InlineData("0", false)]
    [InlineData("0", true)]
    [InlineData("0.0", false)]
    [InlineData("0.0", true)]
    [InlineData("1.0.1", false)]
    [InlineData("1.0.1", true)]
    [InlineData("9.54", false)]
    [InlineData("9.54", true)]
    [InlineData("3.2.454.23436.1", false)]
    [InlineData("3.2.454.23436.1", true)]
    [InlineData("2.123434.1219214.4394", false)]
    [InlineData("2.123434.1219214.4394", true)]
    public void AttributeAsOID(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }

    [Theory]
    [InlineData("objectClass;option1", false)]
    [InlineData("objectClass;option1", true)]
    [InlineData("objectClass;option1;option-2", false)]
    [InlineData("objectClass;option1;option-2", true)]
    [InlineData("objectClass;1option", false)]
    [InlineData("objectClass;1option", true)]
    [InlineData("objectClass;-option", false)]
    [InlineData("objectClass;-option", true)]
    [InlineData("1.2.334.1293;option1", false)]
    [InlineData("1.2.334.1293;option1", true)]
    [InlineData("1.2.334.1293;option1;option-2", false)]
    [InlineData("1.2.334.1293;option1;option-2", true)]
    [InlineData("1.2.334.1293;1option", false)]
    [InlineData("1.2.334.1293;1option", true)]
    [InlineData("1.2.334.1293;-option", false)]
    [InlineData("1.2.334.1293;-option", true)]
    public void AttributeWithOption(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }

    [Theory]
    [InlineData("1attribute=*", 0, 10)] // Must start with a letter
    [InlineData("(1attribute=*)", 1, 11)] // Same as above but wrapped in ()
    [InlineData("(attribute_test=*)", 1, 15)] // Can only contain letters, numbers and -
    [InlineData("1.02.2320=*", 0, 9)] // OID segment must not start with 0 unless it's 0 itself
    [InlineData("attribute;option;=*", 0, 17)] // Option must not end with ;
    public void InvalidAttribute(string filter, int expectedStart, int expectedEnd)
    {
        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Invalid filter attribute value", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Fact]
    public void InvalidSimpleFilterFormat()
    {
        string filter = "=foo";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Simple filter value must not start with '='", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(1, ex.EndPosition);
    }

    [Fact]
    public void InvalidSimpleFilterNoEquals()
    {
        string filter = "foo";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Simple filter missing '=' character", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }

    [Fact]
    public void InvalidSimpleFilterNoValue()
    {
        string filter = "foo=";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Simple filter value is not present after '='", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(4, ex.EndPosition);
    }
}

public class LDAPFilterValueTests
{
    [Theory]
    [InlineData("simple_123", "simple_123")]
    [InlineData("café", "café")]
    [InlineData("test with space", "test with space")]
    [InlineData("null \\00", "null \0")]
    [InlineData("open paren \\28", "open paren (")]
    [InlineData("close paren \\29", "close paren )")]
    [InlineData("asterisk \\2a", "asterisk *")]
    [InlineData("backslash \\5C", "backslash \\")]
    [InlineData("any escaped \\20", "any escaped  ")]
    [InlineData("happy face \\e2\\98\\BA", "happy face ☺")]
    public void ParseSimpleValue(string value, string expected)
    {
        FilterEquality filter = (FilterEquality)LDAPFilter.ParseFilter($"foo={value}");

        string actual = Encoding.UTF8.GetString(filter.Value.Span);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("foo=abc\0", 7, 8)]
    [InlineData("foo=ab(def", 6, 7)]
    public void UnescapedCharacter(string filter, int expectedStart, int expectedEnd)
    {
        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.StartsWith("LDAP filter value contained unescaped char", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData("foo=abc\\ax", 8, 10)]
    [InlineData("foo=\\z3 testing", 5, 7)]
    public void InvalidHexEscape(string filter, int expectedStart, int expectedEnd)
    {
        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.StartsWith("Invalid hex characters following \\ '", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData("foo=test\\a", 8, 10)]
    [InlineData("foo=testing \\", 12, 13)]
    public void NotEnoughHexEscapeChars(string filter, int expectedStart, int expectedEnd)
    {
        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.StartsWith("Not enough escape characters following \\", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }
}
