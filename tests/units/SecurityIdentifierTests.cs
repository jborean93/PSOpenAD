using PSOpenAD.Security;
using System;
using Xunit;

namespace PSOpenADTests;

public static class SecurityIdentifierTests
{
    [Theory]
    [InlineData("S-1-5-21-2707697457-1696005415-603398217-1104", "AQUAAAAAAAUVAAAAMS9koSf9FmVJIPcjUAQAAA==")]
    [InlineData("S-1-5-19", "AQEAAAAAAAUTAAAA")]
    public static void ParseSecurityIdentifierFromString(string sid, string b64Value)
    {
        byte[] expectedBytes = Convert.FromBase64String(b64Value);

        SecurityIdentifier actual = new(sid);
        byte[] actualBytes = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualBytes, 0);

        Assert.Equal(sid, actual.Value);
        Assert.Equal(sid, actual.ToString());
        Assert.Equal(expectedBytes.Length, actual.BinaryLength);
        Assert.Equal(expectedBytes, actualBytes);
    }

    [Theory]
    [InlineData("S-1-5-21-2707697457-1696005415-603398217-1104", "AQUAAAAAAAUVAAAAMS9koSf9FmVJIPcjUAQAAA==")]
    [InlineData("S-1-5-19", "AQEAAAAAAAUTAAAA")]
    public static void ParseSecurityIdentifierFromByte(string sid, string b64Value)
    {
        byte[] sidBytes = Convert.FromBase64String(b64Value);

        SecurityIdentifier actual = new(sidBytes, 0);

        Assert.Equal(sid, actual.Value);
        Assert.Equal(sid, actual.ToString());
        Assert.Equal(sidBytes.Length, actual.BinaryLength);
    }

    [Fact]
    public static void SidEqualsSid()
    {
        SecurityIdentifier sid1 = new SecurityIdentifier("S-1-5-19");
        SecurityIdentifier sid2 = new SecurityIdentifier("S-1-5-19");

        Assert.Equal(sid1, sid2);
    }

    [Fact]
    public static void SidNotEqualString()
    {
        SecurityIdentifier sid1 = new SecurityIdentifier("S-1-5-19");
        string sid2 = "S-1-5-19";

        bool actual = sid1.Equals(sid2);

        Assert.False(actual);
    }

    [Fact]
    public static void ParseSidStringFail()
    {
        var ex = Assert.Throws<ArgumentException>(() => new SecurityIdentifier("S-1-1921-abc"));

        Assert.Equal("sid", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmall()
    {
        SecurityIdentifier sid = new SecurityIdentifier("S-1-5-12921-1921-943-12-3-5");
        var ex = Assert.Throws<ArgumentException>(() => sid.GetBinaryForm(new byte[0], 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallWithOffset()
    {
        SecurityIdentifier sid = new SecurityIdentifier("S-1-5-12921-1921-943-12-3-5");
        byte[] raw = new byte[sid.BinaryLength];
        var ex = Assert.Throws<ArgumentException>(() => sid.GetBinaryForm(raw, 1));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForSubAuthority()
    {
        SecurityIdentifier sid = new SecurityIdentifier("S-1-5-12921-1921-943-12-3-5");
        byte[] raw = new byte[13];
        var ex = Assert.Throws<ArgumentException>(() => sid.GetBinaryForm(raw, 1));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Theory]
    // Capability SIDs aren't real accounts https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#capability-sids
    [InlineData("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681", false)]
    // Built-in SIDs https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
    [InlineData("S-1-5-32-554", false)]
    // domainDNS objects don't have a RID, but do have a domain https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns
    [InlineData("S-1-5-21-3787635890-1162502339-3687787521", true)]
    // Normal SIDs
    [InlineData("S-1-5-21-3137669136-239306048-608292226-1001", true)]
    [InlineData("S-1-5-21-3787635890-1162502339-3687787521-500", true)]
    public static void IsAccountSidIsCorrect(string sid, bool IsAccountSid)
    {
        Assert.Equal(IsAccountSid, (new SecurityIdentifier(sid)).IsAccountSid());
    }

    [Theory]
    [InlineData("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681", null)]
    // Built-in SIDs https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
    [InlineData("S-1-5-32-554", null)]
    // domainDNS objects don't have a RID, but do have a domain https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns
    [InlineData("S-1-5-21-3787635890-1162502339-3687787521", "S-1-5-21-3787635890-1162502339-3687787521")]
    // Normal SIDs
    [InlineData("S-1-5-21-3137669136-239306048-608292226-1001", "S-1-5-21-3137669136-239306048-608292226")]
    [InlineData("S-1-5-21-3787635890-1162502339-3687787521-500", "S-1-5-21-3787635890-1162502339-3687787521")]
    public static void GetAccountDomainSidForAccountIdentifiers(string sid, string AccountDomainSid) {
        if (string.IsNullOrEmpty(AccountDomainSid))
        {
            Assert.Null((new SecurityIdentifier(sid)).AccountDomainSid);
        }
        else
        {
            Assert.Equal(AccountDomainSid, (new SecurityIdentifier(sid)).AccountDomainSid.ToString());
        }
    }
}
