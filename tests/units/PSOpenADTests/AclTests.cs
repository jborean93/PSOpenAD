using PSOpenAD.Security;
using System;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class DiscretionaryAclTests
{
    [Test]
    public async Task ParseDiscrentionaryAcl()
    {
        const string b64Data = "AQBUAAIAAAABBhQAAAIAAAEBAAAAAAAFEgAAAAUGOAAAAQAAAwAAAIAATF4NCURFsZqWdSucHJPk+yxh1BCfTphiaX+wglhBAQEAAAAAAAUTAAAA";
        const string expected = "DiscretionaryAcl 1 AceCount 2";
        byte[] data = Convert.FromBase64String(b64Data);

        DiscretionaryAcl actual = DiscretionaryAcl.ParseAcl(data, out var consumed);

        await Assert.That(consumed).IsEqualTo(data.Length);
        await Assert.That(actual.ToString()).IsEqualTo(expected);
        await Assert.That(actual.Count).IsEqualTo(2);
        await Assert.That(actual.BinaryLength).IsEqualTo(data.Length);
        await Assert.That((int)actual.Revision).IsEqualTo(1);

        await Assert.That(actual[0]).IsTypeOf<Ace>();
        Ace ace1 = actual[0];
        bool contains = actual.Contains(ace1);
        await Assert.That(contains).IsTrue();
        await Assert.That(actual.IndexOf(ace1)).IsEqualTo(0);
        await Assert.That((int)ace1.AccessMask).IsEqualTo(512);
        await Assert.That(ace1.AceFlags).IsEqualTo(AceFlags.ContainerInherit | AceFlags.NoPropagateInherit);
        await Assert.That(ace1.AceType).IsEqualTo(AceType.AccessDenied);
        await Assert.That(ace1.Sid).IsEqualTo(new SecurityIdentifier("S-1-5-18"));
        await Assert.That(ace1.ApplicationData).IsNull();

        await Assert.That(actual[1]).IsTypeOf<ObjectAce>();
        ObjectAce ace2 = (ObjectAce)actual[1];
        contains = actual.Contains(ace2);
        await Assert.That(contains).IsTrue();
        await Assert.That(actual.IndexOf(ace2)).IsEqualTo(1);
        await Assert.That(ace2.AccessMask).IsEqualTo(ActiveDirectoryRights.ExtendedRight);
        await Assert.That(ace2.AceFlags).IsEqualTo(AceFlags.ContainerInherit | AceFlags.NoPropagateInherit);
        await Assert.That(ace2.AceType).IsEqualTo(AceType.AccessAllowedObject);
        await Assert.That(ace2.Sid).IsEqualTo(new SecurityIdentifier("S-1-5-19"));
        await Assert.That(ace2.ApplicationData).IsNull();
        await Assert.That(ace2.ObjectAceFlags).IsEqualTo(ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent);
        await Assert.That(ace2.ObjectAceType).IsEqualTo(new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"));
        await Assert.That(ace2.InheritedObjectAceType).IsEqualTo(new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        byte[] actualBytes = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualBytes, 0);

        await Assert.That(actualBytes).IsEquivalentTo(data);

        int count = 0;
        foreach (Ace ace in actual)
        {
            count++;
        }
        await Assert.That(count).IsEqualTo(2);
    }

    [Test]
    public async Task FailToAddInvalidAce()
    {
        const string expected = "The DiscretionaryAcl ACL does not support an ACE type of AccessAllowedObject";
        Ace ace = new(AceType.AccessAllowedObject, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);

        var ex = await Assert.That(() => acl.Add(ace)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo(expected);
    }

    [Test]
    public async Task FailToAddInsertAce()
    {
        const string expected = "The DiscretionaryAcl ACL does not support an ACE type of SystemAudit";
        Ace ace = new(AceType.SystemAudit, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);

        var ex = await Assert.That(() => acl.Insert(0, ace)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo(expected);
    }

    [Test]
    public async Task CopyTo()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        Ace[] actual = new Ace[2];
        acl.CopyTo(actual, 1);

        await Assert.That(actual[0]).IsNull();
        await Assert.That(actual[1]).IsEqualTo(ace);
    }

    [Test]
    public async Task ClearAcl()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        await Assert.That(acl.Count).IsEqualTo(1);

        acl.Clear();

        await Assert.That(acl.Count).IsEqualTo(0);
    }

    [Test]
    public async Task Remove()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        await Assert.That(acl.Count).IsEqualTo(1);

        acl.Remove(ace);

        await Assert.That(acl.Count).IsEqualTo(0);
    }

    [Test]
    public async Task RemoveAt()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        await Assert.That(acl.Count).IsEqualTo(1);

        acl.RemoveAt(0);

        await Assert.That(acl.Count).IsEqualTo(0);
    }

    [Test]
    public async Task GetBindaryFormTooSmall()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[0];

        var ex = await Assert.That(() => acl.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBindaryFormTooSmallForLength()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[2];

        var ex = await Assert.That(() => acl.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBindaryFormTooSmallForCount()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[4];

        var ex = await Assert.That(() => acl.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBindaryFormTooSmallForReserved()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[6];

        var ex = await Assert.That(() => acl.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }
}
