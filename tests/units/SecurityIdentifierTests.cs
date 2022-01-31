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
}
