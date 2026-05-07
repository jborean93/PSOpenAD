using PSOpenAD.LDAP;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class LDAPErrorTests
{
    [Test]
    public async Task ConvertErrorCodeToMessage()
    {
        const LDAPResultCode code = LDAPResultCode.ProtocolError;
        LDAPResult result = new(code, "match DN", "diagnostic message", null);

        LDAPException exc = new(result);

        await Assert.That(exc.DiagnosticsMessage).IsEqualTo("diagnostic message");
        await Assert.That(exc.ResultCode).IsEqualTo(code);
        await Assert.That(exc.Message).IsEqualTo("Protocol error - diagnostic message");
    }
}
