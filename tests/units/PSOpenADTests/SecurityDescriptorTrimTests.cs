using PSOpenAD.LDAP;
using PSOpenAD.Security;
using System;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class SecurityDescriptorTrimTests
{
    // What a plain read hands back: every component the server was willing to
    // return, which is more than a masked write is allowed to send.
    private static CommonSecurityDescriptor FullDescriptor()
    {
        CommonSecurityDescriptor sd = new()
        {
            Flags = ControlFlags.SelfRelative | ControlFlags.DiscretionaryAclPresent | ControlFlags.SystemAclPresent,
            Owner = new("S-1-5-32-544"),
            Group = new("S-1-5-32-544"),
            DiscretionaryAcl = new(AclRevision.Revision),
            SystemAcl = new(AclRevision.Revision),
        };
        sd.DiscretionaryAcl.Add(new Ace(
            AceType.AccessAllowed,
            AceFlags.None,
            ActiveDirectoryRights.CreateChild,
            new SecurityIdentifier("S-1-1-0"),
            null));
        sd.SystemAcl.Add(new Ace(
            AceType.SystemAudit,
            AceFlags.SuccessfulAccess,
            ActiveDirectoryRights.WriteProperty,
            new SecurityIdentifier("S-1-1-0"),
            null));

        return sd;
    }

    [Test]
    public async Task DaclMaskKeepsOnlyTheDacl()
    {
        CommonSecurityDescriptor trimmed = new(FullDescriptor(), SecurityDescriptorFlags.Dacl);

        await Assert.That(trimmed.Owner).IsNull();
        await Assert.That(trimmed.Group).IsNull();
        await Assert.That(trimmed.SystemAcl).IsNull();
        await Assert.That(trimmed.DiscretionaryAcl).IsNotNull();
    }

    [Test]
    public async Task OwnerMaskKeepsOnlyTheOwner()
    {
        CommonSecurityDescriptor trimmed = new(FullDescriptor(), SecurityDescriptorFlags.Owner);

        await Assert.That(trimmed.Owner).IsNotNull();
        await Assert.That(trimmed.Group).IsNull();
        await Assert.That(trimmed.SystemAcl).IsNull();
        await Assert.That(trimmed.DiscretionaryAcl).IsNull();
    }

    [Test]
    public async Task CombinedMaskKeepsEachComponentItNames()
    {
        CommonSecurityDescriptor trimmed = new(
            FullDescriptor(),
            SecurityDescriptorFlags.Owner | SecurityDescriptorFlags.Group | SecurityDescriptorFlags.Dacl);

        await Assert.That(trimmed.Owner).IsNotNull();
        await Assert.That(trimmed.Group).IsNotNull();
        await Assert.That(trimmed.DiscretionaryAcl).IsNotNull();
        await Assert.That(trimmed.SystemAcl).IsNull();
    }

    // A dropped component must also lose its presence bit, or the server is told
    // a SACL is there while the offset says otherwise.
    [Test]
    public async Task DroppedComponentsLoseTheirPresenceFlag()
    {
        CommonSecurityDescriptor trimmed = new(FullDescriptor(), SecurityDescriptorFlags.Dacl);

        await Assert.That(trimmed.Flags.HasFlag(ControlFlags.SystemAclPresent)).IsFalse();
        await Assert.That(trimmed.Flags.HasFlag(ControlFlags.DiscretionaryAclPresent)).IsTrue();
        await Assert.That(trimmed.Flags.HasFlag(ControlFlags.SelfRelative)).IsTrue();
    }

    [Test]
    public async Task SerializedFormCarriesOnlyTheMaskedComponents()
    {
        byte[] data = new CommonSecurityDescriptor(FullDescriptor(), SecurityDescriptorFlags.Dacl).ToByteArray();

        ushort control = BitConverter.ToUInt16(data, 2);
        await Assert.That(BitConverter.ToUInt32(data, 4)).IsEqualTo(0u);   // owner offset
        await Assert.That(BitConverter.ToUInt32(data, 8)).IsEqualTo(0u);   // group offset
        await Assert.That(BitConverter.ToUInt32(data, 12)).IsEqualTo(0u);  // sacl offset
        await Assert.That(BitConverter.ToUInt32(data, 16)).IsNotEqualTo(0u);
        await Assert.That(control & (ushort)ControlFlags.SystemAclPresent).IsEqualTo(0);
    }
}
