using PSOpenAD.LDAP;
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
        Assert.Equal(((FilterPresent)actual).Attribute, attribute);
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
        Assert.Equal(((FilterPresent)actual).Attribute, attribute);
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
        Assert.Equal(((FilterPresent)actual).Attribute, attribute);
    }

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
        Assert.Equal(((FilterPresent)actual).Attribute, attribute);
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

        Assert.Equal(ex.Filter, filter);
        Assert.Equal(ex.StartPosition, expectedStart);
        Assert.Equal(ex.EndPosition, expectedEnd);
    }
}
