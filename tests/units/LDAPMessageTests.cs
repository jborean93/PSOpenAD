using PSOpenAD.LDAP;
using System;
using Xunit;

namespace PSOpenADTests;

public static class LDAPMessageTests
{
    [Fact]
    public static void SearchResponseDoneWithControl()
    {
        const string MESSAGE = "MIQAAAMJAgENZYQAAAAHCgEABAAEAKCEAAAC8zCEAAAC7QQWMS4yLjg0MC4xMTM1NTYuMS40LjMxOQSEAAACzzCEAAACyQIBAASEAAACwAEAAADAAgAA//////jOd/Kl9wUsx+nNn41F3s26dRJZb9DpebJF84Xvlsv6td5CExPgt0qiBHNEKNnVBAAAAAABAAAA/////7huK1rglnnN680EKOaZzw15WHbBX0J9kXrMYjb0hj7cUAIAAAAAAAABEAgAzMzMzIAAAAAAAAAAAgAAAAAAAAC7WN/BaPaGRK9DlEqKg08iBQAAAEMACgD6BwAAAAAAAPkHAAAAAAAA+gcAAAAAAAAAAAAAAAAAAAIAAAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAABYAQAAAAAAAAEAAAAEAAIAAQAAAAAAAAAAAAAA/////wAAAAD/////AAAAAP8AAAAIAAIADAACABAAAgAKAAAAAAAAAAoAAABETlRfaW5kZXgAAAAAAAAA/wAAAP///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////wAAAAAAWAAAAAAAAAABAAAAFAACAAEAAAAAAAAABzgAAAAAAAD/////oTYAABAnAAAAAAAABQAAABgAAgAAAAAAHAACAAQAAAAAAAAAIAACAAUAAAB/gAA4BwAAAAAAAAAAAAAA";
        LDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(Convert.FromBase64String(MESSAGE), out var _);

        Assert.NotNull(parsedMessage);
        SearchResultDone actual = Assert.IsType<SearchResultDone>(parsedMessage);
        Assert.Equal(LDAPResultCode.Success, actual.Result.ResultCode);
        Assert.Equal("", actual.Result.DiagnosticsMessage);
        Assert.Equal("", actual.Result.MatchedDN);
        Assert.Null(actual.Result.Referrals);

        Assert.NotNull(actual.Controls);
        LDAPControl[] controls = actual.Controls ?? Array.Empty<LDAPControl>();
        LDAPControl control = Assert.Single<LDAPControl>(controls);
        PagedResultControl pagedControl = Assert.IsType<PagedResultControl>(control);
        Assert.Equal(pagedControl.ControlType, PagedResultControl.LDAP_PAGED_RESULT_OID_STRING);
        Assert.False(pagedControl.Criticality);
        Assert.Equal(0, pagedControl.Size);
        Assert.Equal(704, pagedControl.Cookie?.Length);
    }

    [Fact]
    public static void SearchResponseDoneWithReferral()
    {
        const string MESSAGE = "MIQAAADGAgEEZYQAAACMCgEKBAAEUjAwMDAyMDJCOiBSZWZFcnI6IERTSUQtMDMxMDA3OEEsIGRhdGEgMCwgMSBhY2Nlc3MgcG9pbnRzCglyZWYgMTogJ2Zvby5sZGFwLnRlc3QnCgCjhAAAAC0EK2xkYXA6Ly9mb28ubGRhcC50ZXN0L0RDPWZvbyxEQz1sZGFwLERDPXRlc3SghAAAACswhAAAACUEFjEuMi44NDAuMTEzNTU2LjEuNC4zMTkECzCEAAAABQIBAAQA";
        LDAPSession session = new();

        LDAPMessage? parsedMessage = session.ReceiveData(Convert.FromBase64String(MESSAGE), out var _);

        Assert.NotNull(parsedMessage);
        SearchResultDone actual = Assert.IsType<SearchResultDone>(parsedMessage);
        Assert.Equal(LDAPResultCode.Referral, actual.Result.ResultCode);
        Assert.Equal("0000202B: RefErr: DSID-0310078A, data 0, 1 access points\n\tref 1: 'foo.ldap.test'\n\0", actual.Result.DiagnosticsMessage);
        Assert.Equal("", actual.Result.MatchedDN);
        Assert.Single(actual.Result.Referrals);
        Assert.Equal("ldap://foo.ldap.test/DC=foo,DC=ldap,DC=test", actual.Result.Referrals?[0]);
    }
}
