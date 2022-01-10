using System;
using System.Formats.Asn1;

namespace PSOpenAD
{
    internal class Asn1Helper
    {
        /// <summary>Check if there is enough data to decode the ASN.1 payload.</summary>
        /// <remarks>
        /// There is no public API on AsnDecoder to just get the length of the value. Trying to decode an ASN.1
        /// payload without data will result in an <c>AsnContentException</c> but with no way to check if the error
        /// was due to malformed data or just not enough.
        /// </remarks>
        public static bool HasEnoughData(ReadOnlySpan<byte> data)
        {
            Asn1Tag.Decode(data, out int tagLength);
            data = data.Slice(tagLength);
            if (data.Length == 0)
                return false;

            byte firstOctet = data.Slice(0, 1)[0];
            data = data.Slice(1);

            if (firstOctet == 0x80)
            {
                // Indefinite length - try to find 00 00
                int offset = -1;
                while (true)
                {
                    int idx = data.IndexOf<byte>(0);
                    if (idx == -1)
                    {
                        return false;
                    }
                    else if (offset == -1)
                    {
                        offset = idx;
                        data = data.Slice(idx + 1);
                    }
                    else
                    {
                        if (idx == 0)
                            return true;
                        else
                            data = data.Slice(idx + 1);
                    }
                }
            }
            else if (firstOctet < 0x80)
            {
                return data.Length >= firstOctet;
            }
            else if (firstOctet == 0xFF)
            {
                throw new AsnContentException("Illegal ASN.1 length value, cannot decode response");
            }

            byte lengthLength = (byte)(firstOctet & ~0x80);
            if (lengthLength + 1 > data.Length)
            {
                // Need more data
                return false;
            }

            uint length = 0;
            for (int i = 0; i < lengthLength; i++)
            {
                byte currentOctet = data.Slice(i, 1 + i).ToArray()[0];

                if (length == 0 && currentOctet != 0 && lengthLength - i > sizeof(int))
                    throw new AsnContentException("ASN.1 content contains too much data to decode");

                length <<= 8;
                length |= currentOctet;
            }

            if (length > int.MaxValue)
                throw new AsnContentException("ASN.1 content contains too much data to decode");

            return data.Length >= (int)length;
        }
    }
}
