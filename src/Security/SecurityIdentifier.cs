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
}
