using PSOpenAD.Security;
using System;
using System.Threading.Tasks;
using TUnit.Core;
using System.Runtime.InteropServices;

namespace PSOpenADTests;

public class SecurityIdentifierTests
{
    [Test]
    [Arguments("S-1-5-21-2707697457-1696005415-603398217-1104", "AQUAAAAAAAUVAAAAMS9koSf9FmVJIPcjUAQAAA==")]
    [Arguments("S-1-5-19", "AQEAAAAAAAUTAAAA")]
    public async Task ParseSecurityIdentifierFromString(string sid, string b64Value)
    {
        byte[] expectedBytes = Convert.FromBase64String(b64Value);

        SecurityIdentifier actual = new(sid);
        byte[] actualBytes = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualBytes, 0);

        await Assert.That(actual.Value).IsEqualTo(sid);
        await Assert.That(actual.ToString()).IsEqualTo(sid);
        await Assert.That(actual.BinaryLength).IsEqualTo(expectedBytes.Length);
        await Assert.That(actualBytes).IsEquivalentTo(expectedBytes);
    }

    [Test]
    [Arguments("S-1-5-21-2707697457-1696005415-603398217-1104", "AQUAAAAAAAUVAAAAMS9koSf9FmVJIPcjUAQAAA==")]
    [Arguments("S-1-5-19", "AQEAAAAAAAUTAAAA")]
    public async Task ParseSecurityIdentifierFromByte(string sid, string b64Value)
    {
        byte[] sidBytes = Convert.FromBase64String(b64Value);

        SecurityIdentifier actual = new(sidBytes, 0);

        await Assert.That(actual.Value).IsEqualTo(sid);
        await Assert.That(actual.ToString()).IsEqualTo(sid);
        await Assert.That(actual.BinaryLength).IsEqualTo(sidBytes.Length);
    }

    [Test]
    public async Task SidEqualsSid()
    {
        SecurityIdentifier sid1 = new SecurityIdentifier("S-1-5-19");
        SecurityIdentifier sid2 = new SecurityIdentifier("S-1-5-19");

        await Assert.That(sid2).IsEqualTo(sid1);
    }

    [Test]
    public async Task SidEqualsOperatorSid()
    {
        SecurityIdentifier sid1 = new SecurityIdentifier("S-1-5-19");
        SecurityIdentifier sid2 = new SecurityIdentifier("S-1-5-19");
        SecurityIdentifier sid3 = new SecurityIdentifier("S-1-5-18");

        await Assert.That(sid1 == sid2).IsTrue();
        await Assert.That(sid1 == sid3).IsFalse();
    }

    [Test]
    public async Task SidNotEqualsOperatorSid()
    {
        SecurityIdentifier sid1 = new SecurityIdentifier("S-1-5-18");
        SecurityIdentifier sid2 = new SecurityIdentifier("S-1-5-19");
        SecurityIdentifier sid3 = new SecurityIdentifier("S-1-5-18");

        await Assert.That(sid1 != sid2).IsTrue();
        await Assert.That(sid1 != sid3).IsFalse();
    }

    [Test]
    public async Task SidNotEqualString()
    {
        SecurityIdentifier sid1 = new SecurityIdentifier("S-1-5-19");
        string sid2 = "S-1-5-19";

        bool actual = sid1.Equals(sid2);

        await Assert.That(actual).IsFalse();
    }

    [Test]
    public async Task ParseSidStringFail()
    {
        var ex = await Assert.That(() => new SecurityIdentifier("S-1-1921-abc")).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("sid");
    }

    [Test]
    public async Task GetBinaryFormTooSmall()
    {
        SecurityIdentifier sid = new SecurityIdentifier("S-1-5-12921-1921-943-12-3-5");
        var ex = await Assert.That(() => sid.GetBinaryForm(new byte[0], 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallWithOffset()
    {
        SecurityIdentifier sid = new SecurityIdentifier("S-1-5-12921-1921-943-12-3-5");
        byte[] raw = new byte[sid.BinaryLength];
        var ex = await Assert.That(() => sid.GetBinaryForm(raw, 1)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForSubAuthority()
    {
        SecurityIdentifier sid = new SecurityIdentifier("S-1-5-12921-1921-943-12-3-5");
        byte[] raw = new byte[13];
        var ex = await Assert.That(() => sid.GetBinaryForm(raw, 1)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    // Capability SIDs aren't real accounts https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#capability-sids
    [Arguments("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681", false)]
    // Built-in SIDs https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
    [Arguments("S-1-5-32-554", false)]
    // domainDNS objects don't have a RID, but do have a domain https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns
    [Arguments("S-1-5-21-3787635890-1162502339-3687787521", true)]
    // Normal SIDs
    [Arguments("S-1-5-21-3137669136-239306048-608292226-1001", true)]
    [Arguments("S-1-5-21-3787635890-1162502339-3687787521-500", true)]
    public async Task IsAccountSidIsCorrect(string sid, bool IsAccountSid)
    {
        await Assert.That((new SecurityIdentifier(sid)).IsAccountSid()).IsEqualTo(IsAccountSid);
    }

    [Test]
    [Arguments("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681")]
    [Arguments("S-1-5-32-554")]
    public async Task AccountDomainSidReturnsNullForNonAccountIdentifiers(string sid)
    {
        Assert.Null((new SecurityIdentifier(sid)).AccountDomainSid);
    }

    [Test]
    [Arguments("S-1-5-21-3787635890-1162502339-3687787521", "S-1-5-21-3787635890-1162502339-3687787521")]
    [Arguments("S-1-5-21-3137669136-239306048-608292226-1001", "S-1-5-21-3137669136-239306048-608292226")]
    [Arguments("S-1-5-21-3787635890-1162502339-3687787521-500", "S-1-5-21-3787635890-1162502339-3687787521")]
    public async Task AccountDomainSidReturnsDomainSidForAccountIdentifiers(string sid, string AccountDomainSid)
    {
        await Assert.That((new SecurityIdentifier(sid)).AccountDomainSid?.ToString()).IsEqualTo(AccountDomainSid);
    }

    [Test]
    [Arguments("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681", "S-1-15-3-1", false)]
    // Built-in SIDs https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
    [Arguments("S-1-5-32-554", "S-1-5-32-544", true)]
    // domainDNS objects don't have a RID, but do have a domain https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns
    [Arguments("S-1-5-21-3787635890-1162502339-3687787521", "S-1-5-21-3787635890-1162502339-3687787521", true)]
    // Normal SIDs
    [Arguments("S-1-5-21-3137669136-239306048-608292226-1001", "S-1-5-21-3137669136-239306048-608292226", true)]
    [Arguments("S-1-5-21-3787635890-1162502339-3687787521-500", "S-1-5-21-3787635890-1162502339-3687787521", true)]
    [Arguments("S-1-5-11", "S-1-5-11", false)]
    public async Task IsEqualDomainSidIsCorrect(string sidA, string sidB, bool expected)
    {
        await Assert.That((new SecurityIdentifier(sidA)).IsEqualDomainSid(new SecurityIdentifier(sidB))).IsEqualTo(expected);
    }

    [Test]
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public async Task SidRoundtrip()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Skip test on non-Windows platforms
            return;
        }

        SecurityIdentifier sid = new SecurityIdentifier("S-1-5-12921-1921-943-12-3-5");
        System.Security.Principal.SecurityIdentifier winsid = (System.Security.Principal.SecurityIdentifier)sid;
        await Assert.That(winsid.Value).IsEqualTo(sid.Value);
        SecurityIdentifier newsid = (SecurityIdentifier)winsid;
        await Assert.That(newsid.Value).IsEqualTo(sid.Value);
    }
}
