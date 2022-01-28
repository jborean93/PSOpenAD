using System;

namespace PSOpenAD.Security;

/// <summary>
/// The System.DirectoryServices.ActiveDirectoryRights enumeration specifies the access rights that are assigned to an
/// Active Directory Domain Services object.
/// </summary>
[Flags]
public enum ObjectAceRights : uint
{
    /// <summary>
    /// The right to create children of the object.
    /// ADS_RIGHT_DS_CREATE_CHILD
    /// </summary>
    CreateChild = 0x00000001,

    /// <summary>
    /// The right to delete children of the object.
    /// ADS_RIGHT_DS_DELETE_CHILD
    /// </summary>
    DeleteChild = 0x00000002,

    /// <summary>
    /// The right to list children of this object. For more information about this right, see the topic
    /// "Controlling Object Visibility" in the MSDN Library http://msdn.microsoft.com/library.
    /// ADS_RIGHT_ACTRL_DS_LIST
    /// </summary>
    ListChildren = 0x00000004,

    /// <summary>
    /// The right to perform an operation that is controlled by a validated write access right.
    /// ADS_RIGHT_DS_SELF
    /// </summary>
    Self = 0x00000008,

    /// <summary>
    /// The right to read properties of the object.
    /// ADS_RIGHT_DS_READ_PROP
    /// </summary>
    ReadProperty = 0x00000010,

    /// <summary>
    /// The right to write properties of the object.
    /// ADS_RIGHT_DS_WRITE_PROP
    /// </summary>
    WriteProperty = 0x00000020,

    /// <summary>
    /// The right to delete all children of this object, regardless of the permissions of the children.
    /// ADS_RIGHT_DS_DELETE_TREE
    /// </summary>
    DeleteTree = 0x00000040,

    /// <summary>
    /// The right to list a particular object. For more information about this right, see the topic
    /// "Controlling Object Visibility" in the MSDN Library at http://msdn.microsoft.com/library.
    /// ADS_RIGHT_DS_LIST_OBJECT
    /// </summary>
    ListObject = 0x00000080,

    /// <summary>
    /// A customized control access right. For a list of possible extended rights, see the topic "Extended Rights" in
    /// the MSDN Library at http://msdn.microsoft.com. For more information about extended rights, see the topic
    /// "Control Access Rights" in the MSDN Library at http://msdn.microsoft.com.
    /// ADS_RIGHT_DS_CONTROL_ACCESS
    /// </summary>
    ExtendedRight = 0x00000100,

    /// <summary>
    /// The right to delete the object.
    /// ADS_RIGHT_DELETE
    /// </summary>
    Delete = 0x00010000,

    /// <summary>
    /// The right to read data from the security descriptor of the object, not including the data in the SACL.
    /// ADS_RIGHT_READ_CONTROL
    /// </summary>
    ReadControl = 0x00020000,

    /// <summary>
    /// The right to read permissions on, and list the contents of, a container object.
    /// ADS_RIGHT_GENERIC_EXECUTE
    /// </summary>
    GenericExecute = 0x00020004,

    /// <summary>
    /// The right to read permissions on this object, write all the properties on this object, and perform all
    /// validated writes to this object.
    /// ADS_RIGHT_GENERIC_WRITE
    /// </summary>
    GenericWrite = 0x00020028,

    /// <summary>
    /// The right to read permissions on this object, read all the properties on this object, list this object name
    /// when the parent container is listed, and list the contents of this object if it is a container.
    /// ADS_RIGHT_GENERIC_READ
    /// </summary>
    GenericRead = 0x00020094,

    /// <summary>
    /// The right to modify the DACL in the object security descriptor.
    /// ADS_RIGHT_WRITE_DAC
    /// </summary>
    WriteDacl = 0x00040000,

    /// <summary>
    /// The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the
    /// ownership to other users.
    /// ADS_RIGHT_WRITE_OWNER
    /// </summary>
    WriteOwner = 0x00080000,

    /// <summary>
    /// The right to create or delete children, delete a subtree, read and write properties, examine children and the
    /// object itself, add and remove the object from the directory, and read or write with an extended right.
    /// ADS_RIGHT_GENERIC_ALL
    /// </summary>
    GenericAll = 0x000F01FF,

    /// <summary>
    /// The right to use the object for synchronization. This right enables a thread to wait until that object is in
    /// the signaled state.
    /// ADS_RIGHT_SYNCHRONIZE
    /// </summary>
    Synchronize = 0x00100000,

    /// <summary>
    /// The right to get or set the SACL in the object security descriptor.
    /// ADS_RIGHT_ACCESS_SYSTEM_SECURITY
    /// </summary>
    AccessSystemSecurity = 0x01000000
}

public enum AceType : byte
{
    /// <summary>
    /// Allows access to an object for a specific trustee.
    /// ACCESS_ALLOWED_ACE_TYPE
    /// </summary>
    AccessAllowed = 0x00,

    /// <summary>
    /// Denies access to an object for a specific trustee.
    /// ACCESS_DENIED_ACE_TYPE
    /// </summary>
    AccessDenied = 0x01,

    /// <summary>
    /// Causes an audit message to be logged when a specified trustee attempts to gain access to an object.
    /// SYSTEM_AUDIT_ACE_TYPE
    /// </summary>
    SystemAudit = 0x02,

    /// <summary>
    /// Reserved for future use.
    /// SYSTEM_ALARM_ACE_TYPE
    /// </summary>
    SystemAlarm = 0x03,

    /// <summary>
    /// Reserved for future use.
    /// ACCESS_ALLOWED_COMPOUND_ACE_TYPE
    /// </summary>
    AccessAllowedCompound = 0x04,

    /// <summary>
    ///  Allows access to an object, property set, or property. The ACE contains a set of access rights, a GUID that
    /// identifies the type of object, and a identity reference that identifies the trustee to whom the system will
    /// grant access. The ACE also contains a GUID and a set of flags that control inheritance of the ACE by child
    /// objects.
    /// ACCESS_ALLOWED_OBJECT_ACE_TYPE
    /// </summary>
    // Summary:
    //
    AccessAllowedObject = 0x05,

    /// <summary>
    /// Denies access to an object, property set, or property. The ACE contains a set of access rights, a GUID that
    /// identifies the type of object, and an identity reference that identifies the trustee to whom the system will
    /// grant access. The ACE also contains a GUID and a set of flags that control inheritance of the ACE by child
    /// objects.
    /// ACCESS_DENIED_OBJECT_ACE_TYPE
    /// </summary>
    // Summary:
    AccessDeniedObject = 0x06,

    /// <summary>
    /// Causes an audit message to be logged when a specified trustee attempts to gain access to an object or subobjects
    /// such as property sets or properties. The ACE contains a set of access rights, a GUID that identifies the type of
    /// object or subobject, and an identity reference that identifies the trustee for whom the system will audit
    /// access. The ACE also contains a GUID and a set of flags that control inheritance of the ACE by child objects.
    /// SYSTEM_AUDIT_OBJECT_ACE_TYPE
    /// </summary>
    // Summary:
    SystemAuditObject = 0x07,

    /// <summary>
    /// Reserved for future use.
    /// SYSTEM_ALARM_OBJECT_ACE_TYPE
    /// </summary>
    SystemAlarmObject = 0x08,

    /// <summary>
    /// Allows access to an object for a specific trustee identified by an identity reference This ACE type may contain
    /// optional callback data. The callback data is a resource manager-specific BLOB that is not interpreted.
    /// ACCESS_ALLOWED_CALLBACK_ACE_TYPE
    /// </summary>
    AccessAllowedCallback = 0x09,

    /// <summary>
    /// Denies access to an object for a specific trustee identified by an identity reference This ACE type can contain
    /// optional callback data. The callback data is a resource manager-specific BLOB that is not interpreted.
    /// ACCESS_DENIED_CALLBACK_ACE_TYPE
    /// </summary>
    AccessDeniedCallback = 0x0A,

    /// <summary>
    /// Allows access to an object, property set, or property. The ACE contains a set of access rights, a GUID that
    /// identifies the type of object, and an identity reference that identifies the trustee to whom the system will
    /// grant access. The ACE also contains a GUID and a set of flags that control inheritance of the ACE by child
    /// objects. This ACE type may contain optional callback data. The callback data is a resource manager-specific
    /// BLOB that is not interpreted.
    /// ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    /// </summary>
    AccessAllowedCallbackObject = 0x0B,

    /// <summary>
    /// Denies access to an object, property set, or property. The ACE contains a set of access rights, a GUID that
    /// identifies the type of object, and an identity reference that identifies the trustee to whom the system will
    /// grant access. The ACE also contains a GUID and a set of flags that control inheritance of the ACE by child
    /// objects. This ACE type can contain optional callback data. The callback data is a resource manager-specific
    /// BLOB that is not interpreted.
    /// ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    /// </summary>
    AccessDeniedCallbackObject = 0x0C,

    /// <summary>
    /// Causes an audit message to be logged when a specified trustee attempts to gain access to an object. The trustee
    /// is identified by an identity reference. This ACE type can contain optional callback data. The callback data is
    /// a resource manager-specific BLOB that is not interpreted.
    /// SYSTEM_AUDIT_CALLBACK_ACE_TYPE
    /// </summary>
    SystemAuditCallback = 0x0D,

    /// <summary>
    /// Reserved for future use.
    /// SYSTEM_ALARM_CALLBACK_ACE_TYPE
    /// </summary>
    SystemAlarmCallback = 0x0E,

    /// <summary>
    /// Causes an audit message to be logged when a specified trustee attempts to gain access to an object or
    /// subobjects such as property sets or properties. The ACE contains a set of access rights, a GUID that identifies
    /// the type of object or subobject, and an identity reference that identifies the trustee for whom the system will
    /// audit access. The ACE also contains a GUID and a set of flags that control inheritance of the ACE by child
    /// objects. This ACE type can contain optional callback data. The callback data is a resource manager-specific
    /// BLOB that is not interpreted.
    /// SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
    /// </summary>
    SystemAuditCallbackObject = 0x0F,

    /// <summary>
    /// Reserved for future use.
    /// SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    /// </summary>
    SystemAlarmCallbackObject = 0x10,

    /// <summary>
    /// Specifies the mandatory access level and policy for a securable object. The ACE contains access policy mask, and
    /// the access policy level a set by a SID.
    /// SYSTEM_MANDATORY_LABEL_ACE_TYPE
    /// </summary>
    SystemMandatoryLabel = 0x11,

    /// <summary>
    /// Specifies an ACE for the specification of a resource attribute associated with an object. This ACE is used in
    /// conditional ACEs in specifying access or audit policy for the resource.
    /// SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
    /// </summary>
    SystemResourceAttribute = 0x12,

    /// <summary>
    /// Specifies an ACE for the purpose of applying a central access policy to the resource.
    /// SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
    /// </summary>
    SystemScopedPolicyId = 0x13,
}

[Flags]
public enum AceFlags : byte
{
    /// <summary>
    /// No ACE flags are set.
    /// </summary>
    None = 0x00,

    /// <summary>
    /// The access mask is propagated onto child leaf objects.
    /// OBJECT_INHERIT_ACE
    /// </summary>
    ObjectInherit = 0x01,

    /// <summary>
    /// The access mask is propagated to child container objects.
    /// CONTAINER_INHERIT_ACE
    /// </summary>
    ContainerInherit = 0x02,

    /// <summary>
    /// The access checks do not apply to the object; they only apply to its children.
    /// NO_PROPAGATE_INHERIT_ACE
    /// </summary>
    NoPropagateInherit = 0x04,

    /// <summary>
    /// The access mask is propagated only to child objects. This includes both container and leaf child objects.
    /// INHERIT_ONLY_ACE
    /// </summary>
    InheritOnly = 0x08,

    /// <summary>
    /// An ACE is inherited from a parent container rather than being explicitly set for an object.
    /// INHERITED_ACE
    /// </summary>
    Inherited = 0x10,

    /// <summary>
    /// Successful access attempts are audited.
    /// SUCCESSFUL_ACCESS_ACE_FLAG
    /// </summary>
    SuccessfulAccess = 0x40,

    /// <summary>
    /// Failed access attempts are audited.
    /// FAILED_ACCESS_ACE_FLAG
    /// </summary>
    FailedAccess = 0x80,
}

[Flags]
public enum ObjectAceFlags
{
    /// <summary>
    /// No object types are present.
    /// </summary>
    None = 0x00000000,

    /// <summary>
    /// The type of object that is associated with the ACE is present.
    /// ACE_OBJECT_TYPE_PRESENT
    /// </summary>
    ObjectAceTypePresent = 0x00000001,

    /// <summary>
    /// The type of object that can inherit the ACE.
    /// ACE_INHERITED_OBJECT_TYPE_PRESENT
    /// </summary>
    InheritedObjectAceTypePresent = 0x00000002,
}

public class Ace
{
    public int AccessMask { get; set; }
    public AceFlags AceFlags { get; set; }
    public AceType AceType { get; }
    public SecurityIdentifier Sid { get; set; }
    public byte[]? ApplicationData { get; set; }

    public virtual int BinaryLength => ApplicationData?.Length ?? 0 + Sid.BinaryLength + 8;

    public Ace(AceType aceType, AceFlags flags, int accessMask, SecurityIdentifier sid, byte[]? applicationData)
    {
        AceType = aceType;
        AceFlags = flags;
        AccessMask = accessMask;
        Sid = sid;
        ApplicationData = applicationData;
    }

    public override string ToString()
    {
        return string.Format("{0} {1} - 0x{2:X8} {3}", AceType, AceFlags, AccessMask, Sid.Value);
    }

    internal static Ace ParseAce(ReadOnlySpan<byte> data, out int bytesConsumed)
    {
        AceType aceType = (AceType)data[0];
        AceFlags aceFlags = (AceFlags)data[1];
        UInt16 aceSize = BitConverter.ToUInt16(data[2..4]);
        data = data[..aceSize];
        bytesConsumed = aceSize;
        int accessMask = BitConverter.ToInt32(data[4..8]);

        Ace ace;
        if (aceType == AceType.AccessAllowedObject || aceType == AceType.AccessDeniedObject ||
            aceType == AceType.SystemAuditObject || aceType == AceType.SystemAlarmCallbackObject ||
            aceType == AceType.AccessAllowedCallbackObject || aceType == AceType.AccessDeniedCallbackObject ||
            aceType == AceType.SystemAuditCallbackObject || aceType == AceType.SystemAlarmCallbackObject)
        {
            ObjectAceFlags objectAceFlags = (ObjectAceFlags)BitConverter.ToUInt32(data[8..12]);
            Guid objectType = Guid.Empty;
            Guid inheritedObjectType = Guid.Empty;

            int offset = 12;
            if ((objectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
            {
                objectType = new(data.Slice(offset, 16));
                offset += 16;
            }

            if ((objectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
            {
                inheritedObjectType = new(data.Slice(offset, 16));
                offset += 16;
            }

            SecurityIdentifier sid = new(data[offset..]);
            data = data[(offset + sid.BinaryLength)..];

            ace = new ObjectAce(aceType, aceFlags, accessMask, sid, null, objectAceFlags, objectType,
                inheritedObjectType);
        }
        else
        {
            SecurityIdentifier sid = new(data[8..]);
            data = data[(8 + sid.BinaryLength)..];

            ace = new Ace(aceType, aceFlags, accessMask, sid, null);
        }

        if (aceType == AceType.AccessAllowedCallback || aceType == AceType.AccessAllowedCallbackObject ||
            aceType == AceType.AccessDeniedCallback || aceType == AceType.AccessDeniedCallbackObject ||
            aceType == AceType.SystemAuditCallback || aceType == AceType.SystemAuditCallbackObject ||
            aceType == AceType.SystemAuditObject || aceType == AceType.SystemResourceAttribute)
        {
            ace.ApplicationData = data.ToArray();
        }

        return ace;
    }
}

public class ObjectAce : Ace
{
    public Guid InheritedObjectAceType { get; set; }
    public ObjectAceFlags ObjectAceFlags { get; set; }
    public Guid ObjectAceType { get; set; }

    public override int BinaryLength
    {
        get
        {
            int length = 12 + Sid.BinaryLength + (ApplicationData?.Length ?? 0);
            if ((ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
                length += 16;

            if ((ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
                length += 16;

            return length;
        }
    }

    public ObjectAce(AceType aceType, AceFlags flags, int accessMask, SecurityIdentifier sid, byte[]? applicationData,
        ObjectAceFlags objectAceFlags, Guid objectAceType, Guid inheritedObjectAceType)
        : base(aceType, flags, accessMask, sid, applicationData)
    {
        ObjectAceFlags = objectAceFlags;
        ObjectAceType = objectAceType;
        InheritedObjectAceType = inheritedObjectAceType;
    }
}
