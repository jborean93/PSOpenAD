using PSOpenAD.Security;
using System;
using Xunit;

namespace PSOpenADTests;

public static class AceTests
{
    [Fact]
    public static void GetAceToString()
    {
        const string expected = "AccessAllowed ContainerInherit, Inherited - CreateChild S-1-5-19";

        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);

        Assert.Equal(expected, ace.ToString());
    }

    [Fact]
    public static void WriteAceToBytes()
    {
        const string expected = "ABIUAAEAAAABAQAAAAAABRMAAAA=";
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);

        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Fact]
    public static void WriteAceWithAppDataToBytes()
    {
        const string expected = "ABIYAAEAAAABAQAAAAAABRMAAAAAAQID";
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), new byte[] { 0, 1, 2, 3 });

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);

        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Theory]
    [InlineData("ABIUAAEAAAABAQAAAAAABRMAAAA=", AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
        ActiveDirectoryRights.CreateChild, "S-1-5-19", null)]
    [InlineData("CRIYAAEAAAABAQAAAAAABRMAAAAAAQID", AceType.AccessAllowedCallback,
        AceFlags.Inherited | AceFlags.ContainerInherit, ActiveDirectoryRights.CreateChild, "S-1-5-19",
        new byte[] { 0, 1, 2, 3 })]
    public static void ParseAce(string b64Data, AceType expectedType, AceFlags expectedFlags,
        ActiveDirectoryRights expectedMask, string expectedSid, byte[]? expectedData)
    {
        byte[] raw = Convert.FromBase64String(b64Data);

        Ace actual = Ace.ParseAce(raw, out var consumed);
        byte[] actualRaw = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualRaw, 0);

        Assert.Equal(raw.Length, consumed);
        Assert.Equal(expectedType, actual.AceType);
        Assert.Equal(expectedFlags, actual.AceFlags);
        Assert.Equal(expectedMask, actual.AccessMask);
        Assert.Equal(new SecurityIdentifier(expectedSid), actual.Sid);
        Assert.Equal(expectedData, actual.ApplicationData);
        Assert.Equal(raw, actualRaw);
    }

    [Fact]
    public static void GetBinaryFormTooSmall()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(new byte[0], 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallWithOffset()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);
        byte[] raw = new byte[ace.BinaryLength];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 1));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForLength()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);
        byte[] raw = new byte[2];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForMask()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);
        byte[] raw = new byte[4];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }
}

public class ObjectAceTests
{
    [Fact]
    public static void GetAceToString()
    {
        const string expected = "AccessAllowedObject NoPropagateInherit - ExtendedRight S-1-5-19";

        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.InheritedObjectAceTypePresent | ObjectAceFlags.ObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        Assert.Equal(expected, ace.ToString());
    }

    [Fact]
    public static void WriteAceToBytes()
    {
        const string expected = "BQQ4AAABAAADAAAAgABMXg0JREWxmpZ1K5wck+T7LGHUEJ9OmGJpf7CCWEEBAQAAAAAABRMAAAA=";

        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.InheritedObjectAceTypePresent | ObjectAceFlags.ObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);
        string a = Convert.ToBase64String(actual);

        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Fact]
    public static void WriteAceToBytesNoInheritedObjectGuid()
    {
        const string expected = "BQQoAAABAAABAAAAgABMXg0JREWxmpZ1K5wckwEBAAAAAAAFEwAAAA==";

        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);

        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Fact]
    public static void WriteAceToBytesNoObjectGuid()
    {
        const string expected = "BQQoAAABAAACAAAA5PssYdQQn06YYml/sIJYQQEBAAAAAAAFEwAAAA==";

        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);

        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Fact]
    public static void WriteAceToBytesNoInheritedOrObjectGuid()
    {
        const string expected = "BQQYAAABAAAAAAAAAQEAAAAAAAUTAAAA";

        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.None,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);

        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Fact]
    public static void WriteAceToBytesWithAppData()
    {
        const string expected = "CwQ8AAABAAADAAAAgABMXg0JREWxmpZ1K5wck+T7LGHUEJ9OmGJpf7CCWEEBAQAAAAAABRMAAAAAAQID";

        ObjectAce ace = new(
            AceType.AccessAllowedCallbackObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            new byte[] { 0, 1, 2, 3 },
            ObjectAceFlags.InheritedObjectAceTypePresent | ObjectAceFlags.ObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);
        string a = Convert.ToBase64String(actual);

        Assert.Equal(expected, Convert.ToBase64String(actual));
    }

    [Fact]
    public static void GetBinaryFormTooSmall()
    {
        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(new byte[0], 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallWithOffset()
    {
        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));
        byte[] raw = new byte[ace.BinaryLength];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 1));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForLength()
    {
        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));
        byte[] raw = new byte[2];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForMask()
    {
        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));
        byte[] raw = new byte[4];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForObjectAceFlags()
    {
        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));
        byte[] raw = new byte[8];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForObjectAceType()
    {
        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));
        byte[] raw = new byte[12];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Fact]
    public static void GetBinaryFormTooSmallForInheritedObjectAceType()
    {
        ObjectAce ace = new(
            AceType.AccessAllowedObject,
            AceFlags.NoPropagateInherit,
            ActiveDirectoryRights.ExtendedRight,
            new SecurityIdentifier("S-1-5-19"),
            null,
            ObjectAceFlags.ObjectAceTypePresent | ObjectAceFlags.InheritedObjectAceTypePresent,
            new Guid("5e4c0080-090d-4544-b19a-96752b9c1c93"),
            new Guid("612cfbe4-10d4-4e9f-9862-697fb0825841"));
        byte[] raw = new byte[28];

        var ex = Assert.Throws<ArgumentException>(() => ace.GetBinaryForm(raw, 0));

        Assert.Equal("Destination array was not large enough.", ex.Message);
    }

    [Theory]
    [InlineData("BQQ4AAABAAADAAAAgABMXg0JREWxmpZ1K5wck+T7LGHUEJ9OmGJpf7CCWEEBAQAAAAAABRMAAAA=",
        AceType.AccessAllowedObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight, "S-1-5-19",
        null, ObjectAceFlags.InheritedObjectAceTypePresent | ObjectAceFlags.ObjectAceTypePresent,
        "5e4c0080-090d-4544-b19a-96752b9c1c93", "612cfbe4-10d4-4e9f-9862-697fb0825841")]
    [InlineData("BQQoAAABAAABAAAAgABMXg0JREWxmpZ1K5wckwEBAAAAAAAFEwAAAA==",
        AceType.AccessAllowedObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight, "S-1-5-19",
        null, ObjectAceFlags.ObjectAceTypePresent,
        "5e4c0080-090d-4544-b19a-96752b9c1c93", "00000000-0000-0000-0000-000000000000")]
    [InlineData("BQQYAAABAAAAAAAAAQEAAAAAAAUTAAAA",
        AceType.AccessAllowedObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight, "S-1-5-19",
        null, ObjectAceFlags.None, "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000")]
    [InlineData("CwQ8AAABAAADAAAAgABMXg0JREWxmpZ1K5wck+T7LGHUEJ9OmGJpf7CCWEEBAQAAAAAABRMAAAAAAQID",
        AceType.AccessAllowedCallbackObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight,
        "S-1-5-19", new byte[] { 0, 1, 2, 3 },
        ObjectAceFlags.InheritedObjectAceTypePresent | ObjectAceFlags.ObjectAceTypePresent,
        "5e4c0080-090d-4544-b19a-96752b9c1c93", "612cfbe4-10d4-4e9f-9862-697fb0825841")]
    public static void ParseAce(string b64Data, AceType expectedType, AceFlags expectedFlags,
        ActiveDirectoryRights expectedMask, string expectedSid, byte[]? expectedData, ObjectAceFlags expectedAceFlags,
        string expectedObjectActType, string expectedInheritedObjectAceType)
    {
        byte[] raw = Convert.FromBase64String(b64Data);

        ObjectAce actual = (ObjectAce)Ace.ParseAce(raw, out var consumed);
        byte[] actualRaw = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualRaw, 0);

        Assert.Equal(raw.Length, consumed);
        Assert.Equal(expectedType, actual.AceType);
        Assert.Equal(expectedFlags, actual.AceFlags);
        Assert.Equal(expectedMask, actual.AccessMask);
        Assert.Equal(new SecurityIdentifier(expectedSid), actual.Sid);
        Assert.Equal(expectedData, actual.ApplicationData);
        Assert.Equal(expectedAceFlags, actual.ObjectAceFlags);
        Assert.Equal(new Guid(expectedObjectActType), actual.ObjectAceType);
        Assert.Equal(new Guid(expectedInheritedObjectAceType), actual.InheritedObjectAceType);
        Assert.Equal(raw, actualRaw);
    }
}
