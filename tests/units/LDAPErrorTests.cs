using PSOpenAD.LDAP;
using Xunit;

namespace PSOpenADTests;

public class LDAPErrorTests
{
    [Fact]
    public void ConvertErrorCodeToMessage()
    {
        const LDAPResultCode code = LDAPResultCode.ProtocolError;
        LDAPResult result = new(code, "match DN", "diagnostic message", null);

        LDAPException exc = new(result);

        Assert.Equal("diagnostic message", exc.DiagnosticsMessage);
        Assert.Equal(code, exc.ResultCode);
        Assert.Equal("Protocol error - diagnostic message", exc.Message);
    }
}
