using System;

namespace PSOpenAD.Security;

[Flags]
public enum ControlFlags : ushort
{
    /// <summary>
    /// No control flags.
    /// </summary>
    None = 0x0000,

    /// <summary>
    /// Specifies that the owner was obtained by a defaulting mechanism. Set by resource managers only; should not be
    /// set by callers.
    /// </summary>
    OwnerDefaulted = 0x0001,

    /// <summary>
    /// Specifies that the group was obtained by a defaulting mechanism. Set by resource managers only; should not be
    /// set by callers.
    /// </summary>
    GroupDefaulted = 0x0002,

    /// <summary>
    /// Specifies that the DACL is not null. Set by resource managers or users.
    /// </summary>
    DiscretionaryAclPresent = 0x0004,

    /// <summary>
    /// Specifies that the DACL was obtained by a defaulting mechanism. Set by resource managers only.
    /// </summary>
    DiscretionaryAclDefaulted = 0x0008,

    /// <summary>
    /// Specifies that the SACL is not null. Set by resource managers or users.
    /// </summary>
    SystemAclPresent = 0x0010,

    /// <summary>
    /// Specifies that the SACL was obtained by a defaulting mechanism. Set by resource managers only.
    /// </summary>
    SystemAclDefaulted = 0x0020,

    /// <summary>
    /// Ignored.
    /// </summary>
    DiscretionaryAclTrusted = 0x0040,

    /// <summary>
    /// Ignored.
    /// </summary>
    ServerSecurity = 0x0080,

    /// <summary>
    /// Ignored.
    /// </summary>
    DiscretionaryAclAutoInheritRequired = 0x0100,

    /// <summary>
    /// Ignored.
    /// </summary>
    SystemAclAutoInheritRequired = 0x0200,

    /// <summary>
    /// Specifies that the Discretionary Access Control List (DACL) has been automatically inherited from the parent.
    /// Set by resource managers only.
    /// </summary>
    DiscretionaryAclAutoInherited = 0x0400,

    /// <summary>
    /// Specifies that the System Access Control List (SACL) has been automatically inherited from the parent.
    /// Set by resource managers only.
    /// </summary>
    SystemAclAutoInherited = 0x0800,

    /// <summary>
    /// Specifies that the resource manager prevents auto-inheritance. Set by resourcemanagers or users.
    /// </summary>
    DiscretionaryAclProtected = 0x1000,

    /// <summary>
    /// Specifies that the resource manager prevents auto-inheritance. Set by resource managers or users.
    /// </summary>
    SystemAclProtected = 0x2000,

    /// <summary>
    /// Specifies that the contents of the Reserved field are valid.
    /// </summary>
    RMControlValid = 0x4000,

    /// <summary>
    /// Specifies that the security descriptor binary representation is in the self-relative format. This flag is
    /// always set.
    /// </summary>
    SelfRelative = 0x8000,
}

public class CommonSecurityDescriptor
{
    public int BinaryLength => 0;

    public ControlFlags Flags { get; set; }

    public SecurityIdentifier? Owner { get; set; }

    public SecurityIdentifier? Group { get; set; }

    public SystemAcl? SystemAcl { get; set; }

    public DiscretionaryAcl? DiscretionaryAcl { get; set; }

    public CommonSecurityDescriptor(ReadOnlySpan<byte> data)
    {
        Flags = (ControlFlags)BitConverter.ToUInt16(data[2..4]);

        UInt32 offsetOwner = BitConverter.ToUInt32(data[4..8]);
        UInt32 offsetGroup = BitConverter.ToUInt32(data[8..12]);
        UInt32 offsetSacl = BitConverter.ToUInt32(data[12..16]);
        UInt32 offsetDacl = BitConverter.ToUInt32(data[16..20]);

        if (offsetOwner != 0)
        {
            Owner = new(data[(int)offsetOwner..]);
        }

        if (offsetGroup != 0)
        {
            Group = new(data[(int)offsetGroup..]);
        }

        if (offsetSacl != 0)
        {
            SystemAcl = SystemAcl.ParseAcl(data[(int)offsetSacl..], out var _);
        }

        if (offsetDacl != 0)
        {
            DiscretionaryAcl = DiscretionaryAcl.ParseAcl(data[(int)offsetDacl..], out var _);
        }
    }
}
