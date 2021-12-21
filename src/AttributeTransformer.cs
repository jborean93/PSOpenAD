using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace PSOpenAD
{
    public static class DefaultOverrider
    {
        public delegate object? CustomTransform(string attribute, byte[] value);

        internal static Dictionary<string, CustomTransform> Overrides { get; } = DefaultOverrides();

        private static Dictionary<string, CustomTransform> DefaultOverrides()
        {
            // These are known attributes that can map to a more user friendly value. Unfortunately these details
            // aren't stored in the schema so they need to be manually mapped.
            return new Dictionary<string, CustomTransform>()
            {
                // FILETIME value
                { "accountExpires", ((_, v) => AttributeTransformer.ParseFileTimeValue(v)) },
                { "badPasswordTime", ((_, v) => AttributeTransformer.ParseFileTimeValue(v)) },
                { "lastLogoff", ((_, v) => AttributeTransformer.ParseFileTimeValue(v)) },
                { "lastLogon", ((_, v) => AttributeTransformer.ParseFileTimeValue(v)) },
                { "lastLogonTimestamp", ((_, v) => AttributeTransformer.ParseFileTimeValue(v)) },
                { "pwdLastSet", ((_, v) => AttributeTransformer.ParseFileTimeValue(v)) },

                // GroupType enum
                { "groupType", ((_, v) => (GroupType)Int32.Parse(AttributeTransformer.ParseStringValue(v))) },

                // InstanceType enum
                { "instanceType", ((_, v) => (InstanceType)Int32.Parse(AttributeTransformer.ParseStringValue(v))) },

                // SupportedEncryptionTypes enum
                { "msDS-SupportedEncryptionTypes", (
                    (_, v) => (SupportedEncryptionTypes)Int32.Parse(AttributeTransformer.ParseStringValue(v))
                ) },

                // GUID value
                { "objectGUID", ((_, v) => new Guid(v)) },

                // SecurityIdentifier
                { "objectSid", ((_, v) => new SecurityIdentifier(v, 0) ) },

                // SAMAccountType
                { "sAMAccountType", ((_, v) => (SAMAccountType)Int32.Parse(AttributeTransformer.ParseStringValue(v))) },

                // UserAccountControl
                { "userAccountControl", (
                    (_, v) => (UserAccountControl)Int32.Parse(AttributeTransformer.ParseStringValue(v))
                ) },

                // Certificate
                { "userCertificate", ((_, v) => new X509Certificate2(v) ) },
            };
        }
    }

    internal sealed class AttributeTransformer
    {
        private readonly Dictionary<string, AttributeTypes> _typeInformation;

        public AttributeTransformer(Dictionary<string, AttributeTypes> typeInformation)
        {
            _typeInformation = typeInformation;
        }

        public void RegistryTransformer(string attribute, DefaultOverrider.CustomTransform transformer)
            => DefaultOverrider.Overrides[attribute] = transformer;

        public object? Transform(string attribute, byte[][] value)
        {
            AttributeTypes? attrInfo = null;
            if (_typeInformation.ContainsKey(attribute))
                attrInfo = _typeInformation[attribute];

            DefaultOverrider.CustomTransform? customTransform = null;
            if (DefaultOverrider.Overrides.ContainsKey(attribute))
                customTransform = DefaultOverrider.Overrides[attribute];

            List<object?> processed = new List<object?>();
            foreach (byte[] val in value)
            {
                if (customTransform != null)
                {
                    processed.Add(customTransform(attribute, val));
                    continue;
                }

                switch (attrInfo?.Syntax)
                {
                    case "1.2.840.113556.1.4.903": // DNWithOctetString
                        throw new NotImplementedException("DNWithOctetString");

                    case "1.2.840.113556.1.4.904": // DNWithString
                        throw new NotImplementedException("DNWithString");

                    case "1.2.840.113556.1.4.905": // Telex
                        throw new NotImplementedException("Telex");

                    case "1.2.840.113556.1.4.906": // INTEGER8
                        processed.Add(Int64.Parse(ParseStringValue(val)));
                        break;

                    case "1.2.840.113556.1.4.907": // ObjectSecurityDescriptor
                        throw new NotImplementedException("ObjectSecurityDescriptor");

                    case "1.3.6.1.4.1.1466.115.121.1.7": // Boolean
                        processed.Add(ParseStringValue(val) == "TRUE");
                        break;

                    case "1.3.6.1.4.1.1466.115.121.1.24": // GeneralizedTime
                        processed.Add(ParseDateTimeValue(val));
                        break;

                    case "1.3.6.1.4.1.1466.115.121.1.26": // IA5String
                        throw new NotImplementedException("IA5String");

                    case "1.3.6.1.4.1.1466.115.121.1.27": // INTEGER
                        processed.Add(Int32.Parse(ParseStringValue(val)));
                        break;

                    case "1.3.6.1.4.1.1466.115.121.1.36": // NumericString
                        throw new NotImplementedException("NumericString");

                    case "1.3.6.1.4.1.1466.115.121.1.38": // OID
                        processed.Add(ParseStringValue(val));
                        break;

                    case "1.3.6.1.4.1.1466.115.121.1.40": // OctetString
                        processed.Add(val);
                        break;

                    case "1.3.6.1.4.1.1466.115.121.1.43": // PresentationAddress
                        throw new NotImplementedException("PresentationAddress");

                    case "1.3.6.1.4.1.1466.115.121.1.44": // PrintableString
                        throw new NotImplementedException("PrintableString");

                    case "1.3.6.1.4.1.1466.115.121.1.53": // UTCTime
                        throw new NotImplementedException("UTCTime");

                    case "1.3.6.1.4.1.1466.115.121.1.12": // DN
                    case "1.3.6.1.4.1.1466.115.121.1.15": // DirectoryString
                    default:
                        processed.Add(ParseStringValue(val));
                        break;
                }
            }

            return attrInfo?.SingleValue == true ? processed[0] : processed.ToArray();
        }

        internal static DateTime ParseDateTimeValue(byte[] value)
        {
            // Needs to be expanded to support https://ldapwiki.com/wiki/GeneralizedTime
            string rawDT = ParseStringValue(value);
            return DateTime.ParseExact(rawDT, "yyyyMMddHHmmss.fK", CultureInfo.InvariantCulture);
        }

        internal static string ParseStringValue(byte[] value) => Encoding.UTF8.GetString(value);

        internal static DateTime? ParseFileTimeValue(byte[] value)
        {
            Int64 raw = Int64.Parse(ParseStringValue(value));
            if (raw == Int64.MaxValue)
                return null;
            else
                return DateTime.FromFileTimeUtc(raw);
        }
    }
}
