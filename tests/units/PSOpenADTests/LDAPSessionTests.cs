using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Formats.Asn1;
using TUnit.Core;

namespace PSOpenADTests;

internal class CustomLDAPSession : LDAPSession
{
    public CustomLDAPSession() : base()
    {}

    // The test doesn't need to write anything
    public override void WriteData(AsnWriter writer)
    {}
}

public class LDAPSessionTests
{
    [Test]
    public async Task ReceiveFullMessage()
    {
        const string MESSAGE = "MIQAAABBAgEEZYQAAAAHCgEABAAEAKCEAAAAKzCEAAAAJQQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQQLMIQAAAAFAgEABAA=";
        byte[] messageBytes = Convert.FromBase64String(MESSAGE);
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(messageBytes, out var consumed);

        await Assert.That(parsedMessage).IsNotNull();
        await Assert.That(consumed).IsEqualTo(messageBytes.Length);
    }

    [Test]
    public async Task ReceiveFullMessageWithExtraData()
    {
        // Contains 4 extra bytes
        const string MESSAGE = "MIQAAABBAgEEZYQAAAAHCgEABAAEAKCEAAAAKzCEAAAAJQQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQQLMIQAAAAFAgEABAB0ZXN0";
        byte[] messageBytes = Convert.FromBase64String(MESSAGE);
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(messageBytes, out var consumed);

        await Assert.That(parsedMessage).IsNotNull();
        await Assert.That(consumed).IsEqualTo(messageBytes.Length - 4);
    }

    [Test]
    public async Task ReceivePartialMessageOneByteLess()
    {
        // Has 1 byte less than the full size
        const string MESSAGE = "MIQAAABBAgEEZYQAAAAHCgEABAAEAKCEAAAAKzCEAAAAJQQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQQLMIQAAAAFAgEABA==";
        byte[] messageBytes = Convert.FromBase64String(MESSAGE);
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(messageBytes, out var consumed);

        await Assert.That(parsedMessage).IsNull();
        await Assert.That(consumed).IsEqualTo(0);
    }
}
