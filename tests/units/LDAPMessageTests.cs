using PSOpenAD.LDAP;
using System;
using Xunit;

namespace PSOpenADTests;

public class LDAPMessageTests
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
}
