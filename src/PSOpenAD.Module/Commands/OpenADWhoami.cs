using PSOpenAD.LDAP;
using System.Management.Automation;
using System.Text;

namespace PSOpenAD.Module.Commands;

[Cmdlet(
    VerbsCommon.Get, "OpenADWhoami",
    DefaultParameterSetName = "Server"
)]
[OutputType(typeof(WhoamiResult))]
public class GetOpenADWhoami : OpenADSessionCmdletBase
{
    protected override void ProcessRecordWithSession(OpenADSession session)
    {
        int whoamiId = session.Ldap.ExtendedRequest(ExtendedOperations.LDAP_SERVER_WHO_AM_I_OID);
        ExtendedResponse extResp = (ExtendedResponse)session.Connection.WaitForMessage(whoamiId,
            cancelToken: CancelToken);
        if (extResp.Result.ResultCode != LDAPResultCode.Success)
        {
            LDAPException e = new(extResp.Result);
            WriteError(new ErrorRecord(e, "LDAPError", ErrorCategory.ProtocolError, null));
            return;
        }

        string i = extResp.Value == null ? "Unknown" : Encoding.UTF8.GetString(extResp.Value);
        WriteObject(new WhoamiResult(i, session.Uri, session.DomainController, session.Authentication));
    }
}
