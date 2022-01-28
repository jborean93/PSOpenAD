using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace PSOpenAD.Security;

public enum AclRevision : byte
{
    /// <summary>
    /// Standard ACL containing ACEs without an object type.
    /// ACL_REVISION
    /// </summary>
    Revision = 0x02,

    /// <summary>
    /// ACL used for data service objects that contains an object type.
    /// ACL_REVISION_DS
    /// </summary>
    RevisionDS = 0x04,
}

public abstract class Acl : IList<Ace>
{
    private readonly List<Ace> _aces = new();

    private readonly AceType[] _allowedRevisionAceTypes;

    public AclRevision Revision { get; }

    public int BinaryLength => 8 + _aces.Sum(a => a.BinaryLength);

    public int Count => _aces.Count;

    public bool IsReadOnly => false;

    public Ace this[int index]
    {
        get => _aces[index];
        set => _aces[index] = value;
    }

    internal abstract AceType[] AllowedAceTypes { get; }

    protected Acl(AclRevision revision)
    {
        Revision = revision;

        _allowedRevisionAceTypes = Revision == AclRevision.Revision
            ? new[] { AceType.AccessAllowed, AceType.AccessDenied, AceType.SystemAudit, AceType.SystemAlarm,
                AceType.SystemMandatoryLabel, AceType.SystemResourceAttribute, AceType.SystemScopedPolicyId }
            : new[] { AceType.AccessAllowed, AceType.AccessDenied, AceType.SystemAudit, AceType.SystemAlarm,
                AceType.SystemMandatoryLabel, AceType.SystemResourceAttribute, AceType.SystemScopedPolicyId,
                AceType.AccessAllowedObject, AceType.AccessDeniedObject, AceType.SystemAuditObject,
                AceType.SystemAlarmObject, AceType.SystemMandatoryLabel };
    }

    public IEnumerator<Ace> GetEnumerator()
    {
        return _aces.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }

    public void Add(Ace item)
    {
        ValidateAceType(item);
        _aces.Add(item);
    }

    public void Clear() => _aces.Clear();

    public bool Contains(Ace item) => _aces.Contains(item);

    public void CopyTo(Ace[] array, int arrayIndex)
    {
        foreach (Ace ace in array)
        {
            ValidateAceType(ace);
        }

        _aces.CopyTo(array, arrayIndex);
    }

    public bool Remove(Ace item) => _aces.Remove(item);

    public int IndexOf(Ace item) => _aces.IndexOf(item);

    public void Insert(int index, Ace item)
    {
        ValidateAceType(item);
        _aces.Insert(index, item);
    }

    public void RemoveAt(int index) => _aces.RemoveAt(index);

    private void ValidateAceType(Ace ace)
    {
        if (!AllowedAceTypes.Contains(ace.AceType) || !_allowedRevisionAceTypes.Contains(ace.AceType))
        {
            throw new InvalidOperationException(
               $"The {this.GetType().Name} ACL does not support an ACE type of {ace.AceType}");
        }
    }
}

public class DiscretionaryAcl : Acl
{
    internal override AceType[] AllowedAceTypes => new[] { AceType.AccessAllowed, AceType.AccessAllowedCallback,
        AceType.AccessAllowedCallbackObject, AceType.AccessAllowedCompound, AceType.AccessAllowedObject,
        AceType.AccessDenied, AceType.AccessDeniedCallback, AceType.AccessDeniedCallbackObject,
        AceType.AccessDeniedObject };

    protected DiscretionaryAcl(AclRevision revision) : base(revision) { }

    internal static DiscretionaryAcl ParseAcl(ReadOnlySpan<byte> data, out int bytesConsumed)
    {
        AclRevision revision = (AclRevision)data[0];
        UInt16 aclSize = BitConverter.ToUInt16(data[2..4]);
        data = data[..aclSize];
        bytesConsumed = aclSize;
        UInt16 aceCount = BitConverter.ToUInt16(data[4..6]);
        data = data[8..];

        DiscretionaryAcl acl = new(revision);
        for (int i = 0; i < aceCount; i++)
        {
            Ace ace = Ace.ParseAce(data, out var aceConsumed);
            acl.Add(ace);
            data = data[aceConsumed..];
        }

        return acl;
    }
}

public class SystemAcl : Acl
{
    internal override AceType[] AllowedAceTypes => new[] { AceType.SystemAudit, AceType.SystemAuditObject,
        AceType.SystemAuditCallback, AceType.SystemAuditCallbackObject, AceType.SystemMandatoryLabel,
        AceType.SystemResourceAttribute, AceType.SystemScopedPolicyId };

    protected SystemAcl(AclRevision revision) : base(revision) { }

    internal static SystemAcl ParseAcl(ReadOnlySpan<byte> data, out int bytesConsumed)
    {
        AclRevision revision = (AclRevision)data[0];
        UInt16 aclSize = BitConverter.ToUInt16(data[2..4]);
        data = data[..aclSize];
        bytesConsumed = aclSize;
        UInt16 aceCount = BitConverter.ToUInt16(data[4..6]);
        data = data[8..];

        SystemAcl acl = new(revision);
        for (int i = 0; i < aceCount; i++)
        {
            Ace ace = Ace.ParseAce(data, out var aceConsumed);
            acl.Add(ace);
            data = data[aceConsumed..];
        }

        return acl;
    }
}
