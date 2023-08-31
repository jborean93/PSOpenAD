using PSOpenAD.LDAP;
using System;
using System.Formats.Asn1;
using Xunit;

namespace PSOpenADTests;

internal class CustomLDAPSession : LDAPSession
{
    public CustomLDAPSession() : base()
    {}

    // The test doesn't need to write anything
    public override void WriteData(AsnWriter writer)
    {}
}

public static class LDAPSessionTests
{
    [Fact]
    public static void ReceiveFullMessage()
    {
        const string MESSAGE = "MIQAAABBAgEEZYQAAAAHCgEABAAEAKCEAAAAKzCEAAAAJQQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQQLMIQAAAAFAgEABAA=";
        byte[] messageBytes = Convert.FromBase64String(MESSAGE);
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(messageBytes, out var consumed);

        Assert.NotNull(parsedMessage);
        Assert.Equal(messageBytes.Length, consumed);
    }

    [Fact]
    public static void ReceiveFullMessageWithExtraData()
    {
        // Contains 4 extra bytes
        const string MESSAGE = "MIQAAABBAgEEZYQAAAAHCgEABAAEAKCEAAAAKzCEAAAAJQQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQQLMIQAAAAFAgEABAB0ZXN0";
        byte[] messageBytes = Convert.FromBase64String(MESSAGE);
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(messageBytes, out var consumed);

        Assert.NotNull(parsedMessage);
        Assert.Equal(messageBytes.Length - 4, consumed);
    }

    [Fact]
    public static void ReceivePartialMessageOneByteLess()
    {
        // Has 1 byte less than the full size
        const string MESSAGE = "MIQAAABBAgEEZYQAAAAHCgEABAAEAKCEAAAAKzCEAAAAJQQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQQLMIQAAAAFAgEABA==";
        byte[] messageBytes = Convert.FromBase64String(MESSAGE);
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(messageBytes, out var consumed);

        Assert.Null(parsedMessage);
        Assert.Equal(0, consumed);
    }
}
