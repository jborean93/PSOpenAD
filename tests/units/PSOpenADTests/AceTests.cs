using PSOpenAD.Security;
using System;
using System.Threading.Tasks;
using TUnit.Core;

namespace PSOpenADTests;

public class AceTests
{
    [Test]
    public async Task GetAceToString()
    {
        const string expected = "AccessAllowed ContainerInherit, Inherited - CreateChild S-1-5-19";

        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);

        await Assert.That(ace.ToString()).IsEqualTo(expected);
    }

    [Test]
    public async Task WriteAceToBytes()
    {
        const string expected = "ABIUAAEAAAABAQAAAAAABRMAAAA=";
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);

        await Assert.That(Convert.ToBase64String(actual)).IsEqualTo(expected);
    }

    [Test]
    public async Task WriteAceWithAppDataToBytes()
    {
        const string expected = "ABIYAAEAAAABAQAAAAAABRMAAAAAAQID";
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), new byte[] { 0, 1, 2, 3 });

        byte[] actual = new byte[ace.BinaryLength];
        ace.GetBinaryForm(actual, 0);

        await Assert.That(Convert.ToBase64String(actual)).IsEqualTo(expected);
    }

    [Test]
    [Arguments("ABIUAAEAAAABAQAAAAAABRMAAAA=", AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
        ActiveDirectoryRights.CreateChild, "S-1-5-19", null)]
    [Arguments("CRIYAAEAAAABAQAAAAAABRMAAAAAAQID", AceType.AccessAllowedCallback,
        AceFlags.Inherited | AceFlags.ContainerInherit, ActiveDirectoryRights.CreateChild, "S-1-5-19",
        new byte[] { 0, 1, 2, 3 })]
    public async Task ParseAce(string b64Data, AceType expectedType, AceFlags expectedFlags,
        ActiveDirectoryRights expectedMask, string expectedSid, byte[]? expectedData)
    {
        byte[] raw = Convert.FromBase64String(b64Data);

        Ace actual = Ace.ParseAce(raw, out var consumed);
        byte[] actualRaw = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualRaw, 0);

        await Assert.That(consumed).IsEqualTo(raw.Length);
        await Assert.That(actual.AceType).IsEqualTo(expectedType);
        await Assert.That(actual.AceFlags).IsEqualTo(expectedFlags);
        await Assert.That(actual.AccessMask).IsEqualTo(expectedMask);
        await Assert.That(actual.Sid).IsEqualTo(new SecurityIdentifier(expectedSid));
        if (expectedData is null)
            await Assert.That(actual.ApplicationData).IsNull();
        else
            await Assert.That(actual.ApplicationData).IsEquivalentTo(expectedData);
        await Assert.That(actualRaw).IsEquivalentTo(raw);
    }

    [Test]
    public async Task GetBinaryFormTooSmall()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);

        var ex = await Assert.That(() => ace.GetBinaryForm(new byte[0], 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallWithOffset()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);
        byte[] raw = new byte[ace.BinaryLength];

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 1)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForLength()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);
        byte[] raw = new byte[2];

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForMask()
    {
        Ace ace = new(AceType.AccessAllowed, AceFlags.Inherited | AceFlags.ContainerInherit,
            ActiveDirectoryRights.CreateChild, new SecurityIdentifier("S-1-5-19"), null);
        byte[] raw = new byte[4];

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }
}

public class ObjectAceTests
{
    [Test]
    public async Task GetAceToString()
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

        await Assert.That(ace.ToString()).IsEqualTo(expected);
    }

    [Test]
    public async Task WriteAceToBytes()
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

        await Assert.That(Convert.ToBase64String(actual)).IsEqualTo(expected);
    }

    [Test]
    public async Task WriteAceToBytesNoInheritedObjectGuid()
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

        await Assert.That(Convert.ToBase64String(actual)).IsEqualTo(expected);
    }

    [Test]
    public async Task WriteAceToBytesNoObjectGuid()
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

        await Assert.That(Convert.ToBase64String(actual)).IsEqualTo(expected);
    }

    [Test]
    public async Task WriteAceToBytesNoInheritedOrObjectGuid()
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

        await Assert.That(Convert.ToBase64String(actual)).IsEqualTo(expected);
    }

    [Test]
    public async Task WriteAceToBytesWithAppData()
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

        await Assert.That(Convert.ToBase64String(actual)).IsEqualTo(expected);
    }

    [Test]
    public async Task GetBinaryFormTooSmall()
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

        var ex = await Assert.That(() => ace.GetBinaryForm(new byte[0], 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallWithOffset()
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

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 1)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForLength()
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

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForMask()
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

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForObjectAceFlags()
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

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForObjectAceType()
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

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    public async Task GetBinaryFormTooSmallForInheritedObjectAceType()
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

        var ex = await Assert.That(() => ace.GetBinaryForm(raw, 0)).Throws<ArgumentException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Destination array was not large enough.");
    }

    [Test]
    [Arguments("BQQ4AAABAAADAAAAgABMXg0JREWxmpZ1K5wck+T7LGHUEJ9OmGJpf7CCWEEBAQAAAAAABRMAAAA=",
        AceType.AccessAllowedObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight, "S-1-5-19",
        null, ObjectAceFlags.InheritedObjectAceTypePresent | ObjectAceFlags.ObjectAceTypePresent,
        "5e4c0080-090d-4544-b19a-96752b9c1c93", "612cfbe4-10d4-4e9f-9862-697fb0825841")]
    [Arguments("BQQoAAABAAABAAAAgABMXg0JREWxmpZ1K5wckwEBAAAAAAAFEwAAAA==",
        AceType.AccessAllowedObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight, "S-1-5-19",
        null, ObjectAceFlags.ObjectAceTypePresent,
        "5e4c0080-090d-4544-b19a-96752b9c1c93", "00000000-0000-0000-0000-000000000000")]
    [Arguments("BQQYAAABAAAAAAAAAQEAAAAAAAUTAAAA",
        AceType.AccessAllowedObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight, "S-1-5-19",
        null, ObjectAceFlags.None, "00000000-0000-0000-0000-000000000000", "00000000-0000-0000-0000-000000000000")]
    [Arguments("CwQ8AAABAAADAAAAgABMXg0JREWxmpZ1K5wck+T7LGHUEJ9OmGJpf7CCWEEBAQAAAAAABRMAAAAAAQID",
        AceType.AccessAllowedCallbackObject, AceFlags.NoPropagateInherit, ActiveDirectoryRights.ExtendedRight,
        "S-1-5-19", new byte[] { 0, 1, 2, 3 },
        ObjectAceFlags.InheritedObjectAceTypePresent | ObjectAceFlags.ObjectAceTypePresent,
        "5e4c0080-090d-4544-b19a-96752b9c1c93", "612cfbe4-10d4-4e9f-9862-697fb0825841")]
    public async Task ParseAce(string b64Data, AceType expectedType, AceFlags expectedFlags,
        ActiveDirectoryRights expectedMask, string expectedSid, byte[]? expectedData, ObjectAceFlags expectedAceFlags,
        string expectedObjectActType, string expectedInheritedObjectAceType)
    {
        byte[] raw = Convert.FromBase64String(b64Data);

        ObjectAce actual = (ObjectAce)Ace.ParseAce(raw, out var consumed);
        byte[] actualRaw = new byte[actual.BinaryLength];
        actual.GetBinaryForm(actualRaw, 0);

        await Assert.That(consumed).IsEqualTo(raw.Length);
        await Assert.That(actual.AceType).IsEqualTo(expectedType);
        await Assert.That(actual.AceFlags).IsEqualTo(expectedFlags);
        await Assert.That(actual.AccessMask).IsEqualTo(expectedMask);
        await Assert.That(actual.Sid).IsEqualTo(new SecurityIdentifier(expectedSid));
        if (expectedData is null)
            await Assert.That(actual.ApplicationData).IsNull();
        else
            await Assert.That(actual.ApplicationData).IsEquivalentTo(expectedData);
        await Assert.That(actual.ObjectAceFlags).IsEqualTo(expectedAceFlags);
        await Assert.That(actual.ObjectAceType).IsEqualTo(new Guid(expectedObjectActType));
        await Assert.That(actual.InheritedObjectAceType).IsEqualTo(new Guid(expectedInheritedObjectAceType));
        await Assert.That(actualRaw).IsEquivalentTo(raw);
    }
}
