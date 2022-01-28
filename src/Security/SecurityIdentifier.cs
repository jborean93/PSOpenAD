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
        data[2..6].CopyTo(rawAuthority[2..]);
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
        binaryForm[offset] = _revision;
        binaryForm[offset + 1] = (byte)_subAuthorities.Length;

        byte[] authority = BitConverter.GetBytes(_identifierAuthority);
        Array.Reverse(authority);
        Array.Copy(authority, 2, binaryForm, offset + 2, 6);

        for (int i = 0; i < _subAuthorities.Length; i++)
        {
            byte[] rawRid = BitConverter.GetBytes(_subAuthorities[i]);
            Array.Copy(rawRid, 0, binaryForm, offset + 8 + (i * 4), rawRid.Length);
        }
    }

    public override string ToString() => $"S-{_revision}-{_identifierAuthority}-" + String.Join("-", _subAuthorities);
}
