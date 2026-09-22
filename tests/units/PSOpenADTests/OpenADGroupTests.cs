using PSOpenAD;
using PSOpenAD.Security;
using System.Collections.Generic;
using System.Management.Automation;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class OpenADGroupTests
{
    private static OpenADGroup Group(GroupType groupType) => new(new Dictionary<string, (PSObject[], bool)>()
    {
        { "distinguishedName", (new[] { PSObject.AsPSObject("CN=probe,DC=corp,DC=local") }, true) },
        { "name", (new[] { PSObject.AsPSObject("probe") }, true) },
        { "objectClass", (new[] { PSObject.AsPSObject("group") }, true) },
        { "objectSid", (new[] { PSObject.AsPSObject(new SecurityIdentifier("S-1-5-21-1-2-3-512")) }, true) },
        { "groupType", (new[] { PSObject.AsPSObject(groupType) }, true) },
    });

    // A real directory sets IsSecurity on almost every group, so the scope bits
    // have to be masked out before they are compared.
    [Test]
    public async Task SecurityGlobalGroupHasGlobalScope()
    {
        OpenADGroup group = Group(GroupType.Global | GroupType.IsSecurity);

        await Assert.That(group.GroupScope).IsEqualTo(ADGroupScope.Global);
        await Assert.That(group.GroupCategory).IsEqualTo(ADGroupCategory.Security);
    }

    // The builtin Administrators group is 0x80000005: DomainLocal, System and IsSecurity.
    [Test]
    public async Task SecurityDomainLocalBuiltinGroupHasDomainLocalScope()
    {
        OpenADGroup group = Group(GroupType.DomainLocal | GroupType.System | GroupType.IsSecurity);

        await Assert.That(group.GroupScope).IsEqualTo(ADGroupScope.DomainLocal);
    }

    [Test]
    public async Task SecurityUniversalGroupHasUniversalScope()
    {
        OpenADGroup group = Group(GroupType.Universal | GroupType.IsSecurity);

        await Assert.That(group.GroupScope).IsEqualTo(ADGroupScope.Universal);
    }

    // A distribution group carries no IsSecurity bit and was already reported
    // correctly; masking must not change it.
    [Test]
    public async Task DistributionGlobalGroupHasGlobalScope()
    {
        OpenADGroup group = Group(GroupType.Global);

        await Assert.That(group.GroupScope).IsEqualTo(ADGroupScope.Global);
        await Assert.That(group.GroupCategory).IsEqualTo(ADGroupCategory.Distribution);
    }
}
