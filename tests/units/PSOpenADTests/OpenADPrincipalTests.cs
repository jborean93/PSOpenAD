using PSOpenAD;
using PSOpenAD.Security;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class OpenADPrincipalTests
{
    private static Dictionary<string, (PSObject[], bool)> BaseAttributes(string dn) => new()
    {
        { "distinguishedName", (new[] { PSObject.AsPSObject(dn) }, true) },
        { "name", (new[] { PSObject.AsPSObject("probe") }, true) },
        { "objectClass", (new[] { PSObject.AsPSObject("contact") }, true) },
        { "objectGUID", (new[] { PSObject.AsPSObject(System.Guid.Empty) }, true) },
    };

    [Test]
    public async Task PrincipalWithoutObjectSidHasNullSid()
    {
        var attrs = BaseAttributes("CN=probe,DC=corp,DC=local");

        OpenADPrincipal principal = new(attrs);

        await Assert.That(principal.SID).IsNull();
    }

    [Test]
    public async Task PrincipalWithObjectSidKeepsIt()
    {
        const string sid = "S-1-5-21-1-2-3-500";
        var attrs = BaseAttributes("CN=probe,DC=corp,DC=local");
        attrs["objectSid"] = (new[] { PSObject.AsPSObject(new SecurityIdentifier(sid)) }, true);

        OpenADPrincipal principal = new(attrs);

        await Assert.That(principal.SID?.Value).IsEqualTo(sid);
    }
}
