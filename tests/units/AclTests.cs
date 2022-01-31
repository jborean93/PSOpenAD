using PSOpenAD.Security;
using System;
using Xunit;

namespace PSOpenADTests;

public static class DiscretionaryAclTests
{
    [Fact]
    public static void ParseDiscrentionaryAcl()
    {
        const string b64Data = "AQBUAAIAAAABBhQAAAIAAAEBAAAAAAAFEgAAAAUGOAAAAQAAAwAAAIAATF4NCURFsZqWdSucHJPk+yxh1BCfTphiaX+wglhBAQEAAAAAAAUTAAAA";
        const string expected = "DiscretionaryAcl 1 AceCount 2";
        byte[] data = Convert.FromBase64String(b64Data);

        DiscretionaryAcl actual = DiscretionaryAcl.ParseAcl(data, out var consumed);

        Assert.Equal(data.Length, consumed);
        Assert.Equal(expected, actual.ToString());
        Assert.Equal(2, actual.Count);
        Assert.Equal(data.Length, actual.BinaryLength);
        Assert.Equal(1, (byte)actual.Revision);

        Assert.IsType<Ace>(actual[0]);
        Ace ace1 = actual[0];
        bool contains = actual.Contains(ace1);
        Assert.True(contains);
        Assert.Equal(0, actual.IndexOf(ace1));
        Assert.Equal(512, (int)ace1.AccessMask);
        Assert.Equal(AceFlags.ContainerInherit | AceFlags.NoPropagateInherit, ace1.AceFlags);
        Assert.Equal(AceType.AccessDenied, ace1.AceType);
        Assert.Equal(new SecurityIdentifier("S-1-5-18"), ace1.Sid);
        Assert.Null(ace1.ApplicationData);

        Assert.IsType<ObjectAce>(actual[1]);
        ObjectAce ace2 = (ObjectAce)actual[1];
        contains = actual.Contains(ace2);
        Assert.True(contains);
        Assert.Equal(1, actual.IndexOf(ace2));
        Assert.Equal(ActiveDirectoryRights.ExtendedRight, ace2.AccessMask);
        Assert.Equal(AceFlags.ContainerInherit | AceFlags.NoPropagateInherit, ace2.AceFlags);
        Assert.Equal(AceType.AccessAllowedObject, ace2.AceType);
        Assert.Equal(new SecurityIdentifier("S-1-5-19"), ace2.Sid);
        Assert.Null(ace2.ApplicationData);
        Assert.Equal(ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            ace2.ObjectAceFlags);
        Assert.Equal(new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"), ace2.ObjectAceType);
        Assert.Equal(new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"), ace2.InheritedObjectAceType);

        byte[] actualBytes = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualBytes, 0);

        Assert.Equal(data, actualBytes);

        int count = 0;
        foreach (Ace ace in actual)
        {
            count++;
        }
        Assert.Equal(2, count);
    }

    [Fact]
    public static void FailToAddInvalidAce()
    {
        const string expected = "The DiscretionaryAcl ACL does not support an ACE type of AccessAllowedObject";
        Ace ace = new(AceType.AccessAllowedObject, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);

        var ex = Assert.Throws<ArgumentException>(() => acl.Add(ace));

        Assert.Equal(expected, ex.Message);
    }

    [Fact]
    public static void FailToAddInsertAce()
    {
        const string expected = "The DiscretionaryAcl ACL does not support an ACE type of SystemAudit";
        Ace ace = new(AceType.SystemAudit, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);

        var ex = Assert.Throws<ArgumentException>(() => acl.Insert(0, ace));

        Assert.Equal(expected, ex.Message);
    }

    [Fact]
    public static void CopyTo()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        Ace[] actual = new Ace[2];
        acl.CopyTo(actual, 1);

        Assert.Null(actual[0]);
        Assert.Equal(ace, actual[1]);
    }

    [Fact]
    public static void ClearAcl()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        Assert.Single(acl);

        acl.Clear();

        Assert.Empty(acl);
    }

    [Fact]
    public static void Remove()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        Assert.Single(acl);

        acl.Remove(ace);

        Assert.Empty(acl);
    }

    [Fact]
    public static void RemoveAt()
    {
        Ace ace = new(AceType.AccessDenied, AceFlags.None, ActiveDirectoryRights.GenericRead,
            new SecurityIdentifier("S-1-5-19"), null);
        DiscretionaryAcl acl = new(AclRevision.Revision);
        acl.Add(ace);

        Assert.Single(acl);

        acl.RemoveAt(0);

        Assert.Empty(acl);
    }

    [Fact]
    public static void GetBindaryFormTooSmall()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[0];

        var ex = Assert.Throws<ArgumentException>(() => acl.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBindaryFormTooSmallForLength()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[2];

        var ex = Assert.Throws<ArgumentException>(() => acl.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBindaryFormTooSmallForCount()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[4];

        var ex = Assert.Throws<ArgumentException>(() => acl.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBindaryFormTooSmallForReserved()
    {
        DiscretionaryAcl acl = new(AclRevision.Revision);
        byte[] raw = new byte[6];

        var ex = Assert.Throws<ArgumentException>(() => acl.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }
}
