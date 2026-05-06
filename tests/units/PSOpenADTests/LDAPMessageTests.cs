using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class LDAPMessageTests
{
    [Test]
    public async Task SearchResponseDoneWithControl()
    {
        const string MESSAGE = "MIQAAAMJAgENZYQAAAAHCgEABAAEAKCEAAAC8zCEAAAC7QQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQSEAAACzzCEAAACyQIBAASEAAACwAEAAADAAgAA//////jOd/Kl9wUsx+nNn41F3s26dRJZb9DpebJF84Xvlsv6td5CExPgt0qiBHNEKNnVBAAAAAABAAAA/////7huK1rglnnN680EKOaZzw15WHbBX0J9kXrMYjb0hj7cUAIAAAAAAAABEAgAzMzMzIAAAAAAAAAAAgAAAAAAAAC7WN/BaPaGRK9DlEqKg08iBQAAAEMACgD6BwAAAAAAAPkHAAAAAAAA+gcAAAAAAAAAAAAAAAAAAAIAAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAABYAQAAAAAAAAEAAAAEAAIAAQAAAAAAAAAAAAAA/////wAAAAD/////AAAAAP8AAAAIAAIADAACABAAAgAKAAAAAAAAAAoAAABETlRfaW5kZXgAAAAAAAAA/wAAAP///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////wAAAAAAWAAAAAAAAAABAAAAFAACAAEAAAAAAAAABzgAAAAAAAD/////oTYAABAnAAAAAAAABQAAABgAAgAAAAAAHAACAAQAAAAAAAAAIAACAAUAAAB/gAA4BwAAAAAAAAAAAAAA";
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(Convert.FromBase64String(MESSAGE), out var _);

        await Assert.That(parsedMessage).IsNotNull();
        SearchResultDone? actual = await Assert.That(parsedMessage).IsTypeOf<SearchResultDone>();
        await Assert.That(actual).IsNotNull();
        await Assert.That(actual.Result.ResultCode).IsEqualTo(LDAPResultCode.Success);
        await Assert.That(actual.Result.DiagnosticsMessage).IsEqualTo("");
        await Assert.That(actual.Result.MatchedDN).IsEqualTo("");
        await Assert.That(actual.Result.Referrals).IsNull();

        await Assert.That(actual.Controls).IsNotNull();
        LDAPControl[] controls = actual.Controls ?? Array.Empty<LDAPControl>();
        LDAPControl control = await Assert.That(controls).HasSingleItem();
        PagedResultControl? pagedControl = await Assert.That(control).IsTypeOf<PagedResultControl>();
        await Assert.That(pagedControl).IsNotNull();
        await Assert.That(pagedControl.ControlType).IsEqualTo(PagedResultControl.LDAP_PAGED_RESULT_OID_STRING);
        await Assert.That(pagedControl.Criticality).IsFalse();
        await Assert.That(pagedControl.Size).IsEqualTo(0);
        await Assert.That(pagedControl.Cookie?.Length).IsEqualTo(704);
    }

    [Test]
    public async Task SearchResponseDoneWithReferral()
    {
        const string MESSAGE = "MIQAAADGAgEEZYQAAACMCgEKBAAEUjAwMDAyMDJCOiBSZWZFcnI6IERTSUQtMDMxMDA3OEEsIGRhdGEgMCwgMSBhY2Nlc3MgcG9pbnRzCglyZWYgMTogJ2Zvby5sZGFwLnRlc3QnCgCjhAAAAC0EK2xkYXA6Ly9mb28ubGRhcC50ZXN0L0RDPWZvbyxEQz1sZGFwLERDPXRlc3SghAAAACswhAAAACUEFjEuMi44NDAuMTEzNTU2LjEuNC4zMTkECzCEAAAABQIBAAQA";
        CustomLDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(Convert.FromBase64String(MESSAGE), out var _);

        await Assert.That(parsedMessage).IsNotNull();
        SearchResultDone? actual = await Assert.That(parsedMessage).IsTypeOf<SearchResultDone>();
        await Assert.That(actual).IsNotNull();
        await Assert.That(actual.Result.ResultCode).IsEqualTo(LDAPResultCode.Referral);
        await Assert.That(actual.Result.DiagnosticsMessage).IsEqualTo("0000202B: RefErr: DSID-0310078A, data 0, 1 access points\n\tref 1: 'foo.ldap.test'\n\0");
        await Assert.That(actual.Result.MatchedDN).IsEqualTo("");
        await Assert.That(actual.Result.Referrals).IsNotNull();
        await Assert.That(actual.Result.Referrals).HasSingleItem();
        await Assert.That(actual.Result.Referrals?[0]).IsEqualTo("ldap://foo.ldap.test/DC=foo,DC=ldap,DC=test");
    }

    [Test]
    public async Task FailToUnpackMessageInvalidNotASequence()
    {
        const string MESSAGE = "BAR0ZXN0";
        CustomLDAPSession session = new();

        var ex = await Assert.That(() => session.ReceiveData(Convert.FromBase64String(MESSAGE), out var _)).Throws<UnpackLDAPMessageException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Failed to unpack LDAP message: The provided data is tagged with 'Universal' class value '4', but it should have been 'Universal' class value '16'.");
        await Assert.That(ex.LDAPMessage).IsEquivalentTo(Convert.FromBase64String(MESSAGE));
    }

    [Test]
    public async Task FailToUnpackMessageInvalidNotAValidLDAPMsgExtraData()
    {
        const string MESSAGE = "MAR0ZXN0dGVzdA==";
        CustomLDAPSession session = new();

        var ex = await Assert.That(() => session.ReceiveData(Convert.FromBase64String(MESSAGE), out var _)).Throws<UnpackLDAPMessageException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Failed to unpack LDAP message: The provided data is tagged with 'Application' class value '20', but it should have been 'Universal' class value '2'.");
        await Assert.That(ex.LDAPMessage).IsEquivalentTo(Convert.FromBase64String(MESSAGE[..8]));
    }
}
