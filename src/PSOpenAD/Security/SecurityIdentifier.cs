using System;
using System.Text.RegularExpressions;

namespace PSOpenAD.Security;

public sealed class SecurityIdentifier
{
    private readonly byte _revision;
    private readonly UInt64 _identifierAuthority;
    private readonly uint[] _subAuthorities;

    public int BinaryLength => 8 + (_subAuthorities.Length * 4);

    public string Value => ToString();

    /// <value>
    /// The domain SID of the identifier
    /// </value>
    public SecurityIdentifier? AccountDomainSid
    {
        get
        {
            if (IsAccountSid())
            {
                return new SecurityIdentifier(
                    $"S-{_revision}-{_identifierAuthority}-" + String.Join("-", _subAuthorities[0..4])
                );
            }
            else
            {
                return null;
            }
        }
    }

    public SecurityIdentifier(string sid)
    {
        Match m = Regex.Match(sid, @"^S-(?<revision>\d)-(?<authority>\d+)(?:-\d+){1,15}$");
        if (m.Success)
        {
            _revision = byte.Parse(m.Groups["revision"].Value);
            _identifierAuthority = UInt64.Parse(m.Groups["authority"].Value);
            string[] sidSplit = sid.Split('-');

            _subAuthorities = new uint[sidSplit.Length - 3];
            for (int i = 3; i < sidSplit.Length; i++)
            {
                _subAuthorities[i - 3] = uint.Parse(sidSplit[i]);
            }
        }
        else
        {
            throw new ArgumentException(nameof(sid));
        }
    }

    public SecurityIdentifier(byte[] binaryForm, int offset) : this(binaryForm.AsSpan()[offset..]) { }

    internal SecurityIdentifier(ReadOnlySpan<byte> data)
    {
        _revision = data[0];

        Span<byte> rawAuthority = stackalloc byte[8];
        data[2..8].CopyTo(rawAuthority[2..]);
        if (BitConverter.IsLittleEndian)
            rawAuthority.Reverse();
        _identifierAuthority = BitConverter.ToUInt64(rawAuthority);

        _subAuthorities = new uint[data[1]];
        for (int i = 0; i < _subAuthorities.Length; i++)
        {
            int idOffset = 8 + (i * 4);
            _subAuthorities[i] = BitConverter.ToUInt32(data[idOffset..]);
        }
    }

    public void GetBinaryForm(byte[] binaryForm, int offset)
    {
        Span<byte> data = binaryForm.AsSpan()[offset..];

        WriteBinaryForm(data);
    }

    internal byte[] ToByteArray()
    {
        byte[] data = new byte[BinaryLength];
        WriteBinaryForm(data);

        return data;
    }

    internal void WriteBinaryForm(Span<byte> data)
    {
        if (!BitConverter.TryWriteBytes(data, _identifierAuthority))
            throw new ArgumentException("Destination array was not large enough.");
        if (BitConverter.IsLittleEndian)
            data[..8].Reverse();

        data[0] = _revision;
        data[1] = (byte)_subAuthorities.Length;
        data = data[8..];

        foreach (uint subAuthority in _subAuthorities)
        {
            if (!BitConverter.TryWriteBytes(data, subAuthority))
                throw new ArgumentException("Destination array was not large enough.");

            data = data[4..];
        }
    }

    public override bool Equals(object? obj)
    {
        if (obj is SecurityIdentifier)
        {
            return Value == ((SecurityIdentifier)obj).Value;
        }
        else
        {
            return base.Equals(obj);
        }
    }

    public override int GetHashCode()
    {
        return Value.GetHashCode();
    }

    public override string ToString() => $"S-{_revision}-{_identifierAuthority}-" + String.Join("-", _subAuthorities);

    /// <summary>
    /// Test if the identifier is a valid Windows account SID.
    /// </summary>
    public bool IsAccountSid()
        => _identifierAuthority == 5 && _subAuthorities.Length >= 4 && _subAuthorities[0] == 21;
    // 21 is a fixed value used for "normal" issuing authorities
    // Normal SID layout is 4 subauthorities and RID
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-azod/ecc7dfba-77e1-4e03-ab99-114b349c7164

    /// <summary>
    /// Test if the identifier belongs to the same domain as the specified SID
    /// </summary>
    public bool IsEqualDomainSid(SecurityIdentifier sid)
    {
        if (_identifierAuthority != 5 || sid._identifierAuthority != 5)
        {
            return false;
        }
        else if (IsAccountSid() && sid.IsAccountSid())
        {
            return AccountDomainSid!.Equals(sid.AccountDomainSid);
        }
        else if (_subAuthorities.Length >= 1 && _subAuthorities[0] == 32 &&
                    sid._subAuthorities.Length >= 1 && _subAuthorities[0] == 32)
        {
            return _subAuthorities[0] == sid._subAuthorities[0];
        }
        else
        {
            return false;
        }
    }

    public static bool operator ==(SecurityIdentifier? a, SecurityIdentifier? b) => a is null ? b is null : a.Equals(b);
    public static bool operator !=(SecurityIdentifier? a, SecurityIdentifier? b) => !(a == b);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static implicit operator System.Security.Principal.SecurityIdentifier(SecurityIdentifier sid)
        => new System.Security.Principal.SecurityIdentifier(sid.Value);

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static implicit operator SecurityIdentifier(System.Security.Principal.SecurityIdentifier sid)
        => new SecurityIdentifier(sid.Value);
}
