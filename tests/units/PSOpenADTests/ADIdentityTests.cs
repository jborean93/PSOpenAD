using PSOpenAD;
using PSOpenAD.LDAP;
using System;
using System.Text;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class ADPrincipalIdentityTests
{
    [Test]
    [Arguments("user", "user")]
    [Arguments("DOMAIN\\user", "user")]
    [Arguments("Some User (12345)", "Some User (12345)")]
    [Arguments("DOMAIN\\Some User (12345)", "Some User (12345)")]
    [Arguments("(user)", "(user)")]
    [Arguments("user$", "user$")]
    [Arguments("user.name-1_2", "user.name-1_2")]
    [Arguments("café", "café")]
    public async Task ParsesSamAccountName(string value, string expected)
    {
        ADPrincipalIdentity identity = new(value);

        await Assert.That(identity.DistinguishedName).IsNull();
        FilterEquality filter = (FilterEquality)identity.LDAPFilter;
        await Assert.That(filter.Attribute).IsEqualTo("sAMAccountName");
        await Assert.That(Encoding.UTF8.GetString(filter.Value.Span)).IsEqualTo(expected);
    }

    [Test]
    [Arguments("Some Computer (12345)", "Some Computer (12345)$")]
    [Arguments("Some Computer (12345)$", "Some Computer (12345)$")]
    [Arguments("computer", "computer$")]
    public async Task ParsesSamAccountNameWithDollar(string value, string expected)
    {
        ADPrincipalIdentityWithDollar identity = new(value);

        await Assert.That(identity.DistinguishedName).IsNull();
        FilterEquality filter = (FilterEquality)identity.LDAPFilter;
        await Assert.That(filter.Attribute).IsEqualTo("sAMAccountName");
        await Assert.That(Encoding.UTF8.GetString(filter.Value.Span)).IsEqualTo(expected);
    }

    [Test]
    [Arguments("CN=Some User (12345),OU=Staff,DC=domain,DC=test")]
    [Arguments("CN=user,DC=domain,DC=test")]
    [Arguments("user;name")]
    [Arguments("user:name")]
    [Arguments("user\"name")]
    [Arguments("user<name")]
    [Arguments("user>name")]
    [Arguments("user|name")]
    [Arguments("user?name")]
    [Arguments("user,name")]
    [Arguments("user=name")]
    [Arguments("user*name")]
    [Arguments("user+name")]
    [Arguments("user\\name\\other")]
    public async Task FallsBackToDistinguishedName(string value)
    {
        ADPrincipalIdentity identity = new(value);

        await Assert.That(identity.DistinguishedName).IsEqualTo(value);
        await Assert.That(identity.LDAPFilter).IsTypeOf<FilterPresent>();
        await Assert.That(((FilterPresent)identity.LDAPFilter).Attribute).IsEqualTo("objectClass");
    }

    [Test]
    [Arguments("user@domain.test")]
    [Arguments("some user (12345)@domain.test")]
    public async Task ParsesUserPrincipalName(string value)
    {
        ADPrincipalIdentity identity = new(value);

        await Assert.That(identity.DistinguishedName).IsNull();
        FilterEquality filter = (FilterEquality)identity.LDAPFilter;
        await Assert.That(filter.Attribute).IsEqualTo("userPrincipalName");
        await Assert.That(Encoding.UTF8.GetString(filter.Value.Span)).IsEqualTo(value);
    }

    [Test]
    public async Task ParsesObjectGuid()
    {
        Guid guid = Guid.NewGuid();
        ADPrincipalIdentity identity = new(guid.ToString());

        await Assert.That(identity.DistinguishedName).IsNull();
        FilterEquality filter = (FilterEquality)identity.LDAPFilter;
        await Assert.That(filter.Attribute).IsEqualTo("objectGUID");
        await Assert.That(filter.Value.ToArray()).IsEquivalentTo(guid.ToByteArray());
    }

    [Test]
    public async Task ParsesSecurityIdentifier()
    {
        ADPrincipalIdentity identity = new("S-1-5-21-1-2-3-500");

        await Assert.That(identity.DistinguishedName).IsNull();
        FilterEquality filter = (FilterEquality)identity.LDAPFilter;
        await Assert.That(filter.Attribute).IsEqualTo("objectSid");
        await Assert.That(filter.Value.Length).IsEqualTo(28);
    }
}
