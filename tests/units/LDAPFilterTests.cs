using PSOpenAD.LDAP;
using Xunit;

namespace PSOpenADTests;

public class LDAPFilterTests
{
    [Fact]
    public void Test1()
    {
        const string PRESENT_FILTER = "objectClass=*";

        LDAPFilter actual = LDAPFilter.ParseFilter(PRESENT_FILTER);

        Assert.IsType<FilterPresent>(actual);
    }
}
