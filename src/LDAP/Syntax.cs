using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace PSOpenAD.LDAP;

public static class SyntaxDefinition
{
    /// <summary>Reads an Attribute Type Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.3 DESC 'Attribute Type Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed Attribute Type Description string in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.1">RFC 4517 3.3.1. Attribute Type Description</see>
    public static string ReadAttributeTypeDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a Bit String.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.6 DESC 'Bit String' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed bytes that the bit string represents.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.2">RFC 4517 3.3.2. Bit String</see>
    public static byte[] ReadBitString(ReadOnlySpan<byte> data)
    {
        string raw = Encoding.ASCII.GetString(data);
        raw = raw.Substring(1, raw.Length - 3); // Strip surrounding single quotes and remaining B.
        int numBytes = (int)Math.Ceiling((decimal)raw.Length / 8);
        raw = raw.PadLeft(numBytes * 8, '0');

        var bytes = Enumerable.Range(0, numBytes)
            .Select(i => Convert.ToByte(raw.Substring(8 * i, 8), 2))
            .ToArray();

        return bytes;
    }

    /// <summary>Reads a boolean value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.7 DESC 'Boolean' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>Whether the value was true or not.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.3">RFC 4517 3.3.3. Boolean</see>
    public static bool ReadBoolean(ReadOnlySpan<byte> data)
    {
        // data == TRUE
        return data.Length == 4 && data[0] == 0x54 && data[1] == 0x52 && data[2] == 0x55 && data[3] == 0x45;
    }

    /// <summary>Reads a country string value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.11 DESC 'Country String' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The 2 character country string value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.4">RFC 4517 3.3.4. Country String</see>
    public static string ReadCountryString(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a DN value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.12 DESC 'DN' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The DN string value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.9">RFC 4517 3.3.9. DN</see>
    public static string ReadDN(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a delivery method value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.14 DESC 'Delivery Method' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The delivery methods of the value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.5">RFC 4517 3.3.5. Delivery Method</see>
    public static string[] ReadDeliveryMethod(ReadOnlySpan<byte> data)
    {
        string raw = Encoding.UTF8.GetString(data);

        return raw.Split(" $ ");
    }

    /// <summary>Reads a directory string value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed directory string value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.6">RFC 4517 3.3.5. Directory String</see>
    public static string ReadDirectoryString(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a DIT Content Rule Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.16 DESC 'DIT Content Rule Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed Context Rule Description string in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.7">RFC 4517 3.3.7. DIT Content Rule Description</see>
    public static string ReadDITContentRuleDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a DIT Structure Rule Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.17 DESC 'DIT Structure Rule Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed Structure Rule Description string in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.8">RFC 4517 3.3.8. DIT Structure Rule Description</see>
    public static string ReadDITStructureRuleDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads an Enhanced Guide value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.21 DESC 'Enhanced Guide' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The Enhanced Guide string in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.10">RFC 4517 3.3.10. Enhanced Guide</see>
    public static string ReadEnhancedGuide(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads an Facsimile Telephone Number.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.22 DESC 'Facsimile Telephone Number')
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The Facsimile Telephone Number.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.11">RFC 4517 3.3.11. Facsimile Telephone Number</see>
    public static string ReadFacsimileTelephoneNumber(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a Fax image.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.23 DESC 'Fax' )
    /// The ASN.1 definition for this field is.
    /// Fax ::= CHOICE {
    ///     g3-facsimile  [3] G3FacsimileBodyPart
    /// }
    ///
    /// simileBodyPart ::= SEQUENCE {
    ///     parameters G3FacsimileParameters,
    ///     data G3FacsimileData
    /// }
    ///
    /// g3-facsimile-body-part EXTENDED-BODY-PART-TYPE ::= {
    ///     PARAMETERS {G3FacsimileParameters IDENTIFIED BY id-ep-g3-facsimile},
    ///     DATA {G3FacsimileData IDENTIFIED BY id-et-g3-facsimile}
    /// }
    ///
    /// G3FacsimileParameters ::= SET {
    ///     number-of-pages [0] INTEGER OPTIONAL,
    ///     non-basic-parameters [1] G3FacsimileNonBasicParameters OPTIONAL
    /// }
    ///
    /// G3FacsimileData ::= SEQUENCE OF BIT STRING
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The raw fax data.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.12">RFC 4517 3.3.12. Fax</see>
    public static byte[] ReadFax(ReadOnlySpan<byte> data) => data.ToArray();

    /// <summary>Reads a generialized time value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///      ( 1.3.6.1.4.1.1466.115.121.1.24 DESC 'Generalized Time' )
    /// The ABNF notation of this field is:
    ///     GeneralizedTime = century year month day hour
    ///                         [ minute [ second / leap-second ] ]
    ///                         [ fraction ]
    ///                         g-time-zone
    ///
    ///     century = 2(%x30-39) ; "00" to "99"
    ///     year    = 2(%x30-39) ; "00" to "99"
    ///     month   =   ( %x30 %x31-39 ) ; "01" (January) to "09"
    ///             / ( %x31 %x30-32 ) ; "10" to "12"
    ///     day     =   ( %x30 %x31-39 )    ; "01" to "09"
    ///             / ( %x31-32 %x30-39 ) ; "10" to "29"
    ///             / ( %x33 %x30-31 )    ; "30" to "31"
    ///     hour    = ( %x30-31 %x30-39 ) / ( %x32 %x30-33 ) ; "00" to "23"
    ///     minute  = %x30-35 %x30-39                        ; "00" to "59"
    ///
    ///     second      = ( %x30-35 %x30-39 ) ; "00" to "59"
    ///     leap-second = ( %x36 %x30 )       ; "60"
    ///     fraction        = ( DOT / COMMA ) 1*(%x30-39)
    ///     g-time-zone     = %x5A  ; "Z"
    ///                     / g-differential
    ///     g-differential  = ( MINUS / PLUS ) hour [ minute ]
    ///     MINUS           = %x2D  ; minus sign ("-")
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The generalized date time value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.13">RFC 4517 3.3.13. Generalized Time</see>
    public static DateTimeOffset ReadGeneralizedTime(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<char> value = Encoding.ASCII.GetString(data).AsSpan();
        int tzOffset = value.IndexOfAny(new[] { 'Z', '-', '+' });
        ReadOnlySpan<char> tzValue = value[tzOffset..];
        value = value[..tzOffset];

        int year = int.Parse(value[0..4]);
        int month = int.Parse(value[4..6]);
        int day = int.Parse(value[6..8]);
        long hourTicks = TimeSpan.TicksPerHour * int.Parse(value[8..10]);
        long minuteTicks = 0;
        long secondTicks = 0;
        bool minuteSet = false;
        bool secondSet = false;

        value = value[10..];
        if (value.Length > 0 && value[0] != '.' && value[0] != ',')
        {
            minuteSet = true;
            minuteTicks = TimeSpan.TicksPerMinute * int.Parse(value[..2]);
            value = value[2..];
        }

        if (value.Length > 0 && value[0] != '.' && value[0] != ',')
        {
            secondSet = true;
            secondTicks = TimeSpan.TicksPerSecond * int.Parse(value[..2]);
            value = value[2..];
        }

        if (value.Length > 0)
        {
            double fraction = double.Parse($"0.{value[1..].ToString()}");

            if (fraction != 0)
            {
                if (secondSet)
                {
                    secondTicks = (long)(secondTicks * fraction);
                }
                else if (minuteSet)
                {
                    minuteTicks = (long)(minuteTicks * fraction);
                }
                else
                {
                    hourTicks = (long)(hourTicks * fraction);
                }
            }
        }

        TimeSpan tz;
        if (tzValue.ToString() == "Z")
        {
            tz = TimeSpan.Zero;
        }
        else
        {
            int tzHour = int.Parse(tzValue[1..3]);
            int tzMinute = 0;
            if (tzValue.Length > 3)
                tzMinute = int.Parse(tzValue[3..5]);

            tz = new TimeSpan(tzHour, tzMinute, 0);
            if (tzValue[0] == '-')
                tz = -tz;
        }

        DateTimeOffset dt = new DateTimeOffset(year, month, day, 0, 0, 0, tz);
        return dt.AddTicks(hourTicks + minuteTicks + secondTicks);
    }

    /// <summary>Reads a Guide value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.25 DESC 'Guide' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The Guide value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.14">RFC 4517 3.3.14. Guide</see>
    public static string ReadGuide(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads an IA5 String value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.26 DESC 'IA5 String' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The string value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.15">RFC 4517 3.3.15. IA5 String</see>
    public static string ReadIA5String(ReadOnlySpan<byte> data) => Encoding.ASCII.GetString(data);

    /// <summary>Reads an integer value.</summary>
    /// <remarks>
    /// There is no limit to the size that an integer can represent so a BigInteger is used.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.27 DESC 'INTEGER' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The integer value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.16">RFC 4517 3.3.16. Integer</see>
    public static BigInteger ReadInteger(ReadOnlySpan<byte> data)
    {
        string value = Encoding.ASCII.GetString(data);

        return BigInteger.Parse(value);
    }

    /// <summary>Reads a JPEG image.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.28 DESC 'JPEG' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The JPEG bytes.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.17">RFC 4517 3.3.17. JPEG</see>
    public static byte[] ReadJPEG(ReadOnlySpan<byte> data) => data.ToArray();

    /// <summary>Reads an Matching Rule Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.30 DESC 'Matching Rule Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed Matching Rule Description in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.19">RFC 4517 3.3.19. Matching Rule Description</see>
    public static string ReadMatchingRuleDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads an Matching Rule Use Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.31 DESC 'Matching Rule Use Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed Matching Rule Use Description in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.19">RFC 4517 3.3.19. Matching Rule Use Description</see>
    public static string ReadMatchingRuleUseDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a name and optional UID of an entity.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The ABNF form is:
    ///     NameAndOptionalUID = distinguishedName [ SHARP BitString ]
    ///
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.34 DESC 'Name And Optional UID' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The entity name with optional UID.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.21">RFC 4517 3.3.21. Name and Optional UID</see>
    public static string ReadNameAndOptionalUID(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a Name Form Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.35 DESC 'Name Form Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed Name Form Description in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.22">RFC 4517 3.3.22. Name Form Description</see>
    public static string ReadNameFormDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a numeric string.</summary>
    /// <remarks>
    /// There is size limit on each numeric part.
    ///
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.36 DESC 'Numeric String' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>An array of each numeric entry.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.23">RFC 4517 3.3.23. Numeric String</see>
    public static BigInteger[] ReadNumericString(ReadOnlySpan<byte> data)
    {
        string value = Encoding.ASCII.GetString(data);

        return value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(v => BigInteger.Parse(v)).ToArray();
    }

    /// <summary>Reads an Object Class Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.37 DESC 'Object Class Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed Object Class Description in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.24">RFC 4517 3.3.24. Object Class Description</see>
    public static string ReadObjectClassDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads an object identifer (OID).</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.38 DESC 'OID' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The object identifier as a string.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.26">RFC 4517 3.3.26. OID</see>
    public static string ReadOID(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads the Other Mailbox value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.39 DESC 'Other Mailbox' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The other mailbox value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.27">RFC 4517 3.3.27. Other Mailbox</see>
    public static string ReadOtherMailbox(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads an Octet String.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.40 DESC 'Octet String' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The raw bytes.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.25">RFC 4517 3.3.25. Octet String</see>
    public static byte[] ReadOctetString(ReadOnlySpan<byte> data) => data.ToArray();

    /// <summary>Reads a Postal Address.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.41 DESC 'Postal Address' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The postal address lines.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.28">RFC 4517 3.3.28. Postal Address</see>
    public static string[] ReadPostalAddress(ReadOnlySpan<byte> data)
    {
        string value = Encoding.UTF8.GetString(data);

        return value.Split('$').Select(v => v.Replace("\\24", "$").Replace("\\5C", "\\")).ToArray();
    }

    /// <summary>Reads a Presentation Address value.</summary>
    /// <remarks>
    /// This is no longer defined in RFC 4517 but AD still uses it for the <c>presentationAddress</c> attribute.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.43 DESC 'Presentation Address' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The string value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc2252#section-6.28">RFC 2252 6.28. Presentation Address</see>
    public static string ReadPresentationAddress(ReadOnlySpan<byte> data) => Encoding.ASCII.GetString(data);

    /// <summary>Reads a Printable String value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.44 DESC 'Printable String' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The string value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.29">RFC 4517 3.3.29. Printable String</see>
    public static string ReadPrintableString(ReadOnlySpan<byte> data) => Encoding.ASCII.GetString(data);

    /// <summary>Reads a Telephone Number value.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.50 DESC 'Telephone Number' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The telephone number value.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.31">RFC 4517 3.3.31. Telephone Number</see>
    public static string ReadTelephoneNumber(ReadOnlySpan<byte> data) => Encoding.ASCII.GetString(data);

    /// <summary>Reads a Teletex Terminal Identifier.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The teletex terminal identifier.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.32">RFC 4517 3.3.32. Teletex Terminal Identifier</see>
    public static TeletexTerminalIdentifier ReadTeletexTerminalIdentifier(ReadOnlySpan<byte> data)
        => new TeletexTerminalIdentifier(data);

    /// <summary>Reads a Telex Number.</summary>
    /// <remarks>
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.52 DESC 'Telex Number' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The telex number, the number, country code, and answer back are separated by <c>$</c></returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.33">RFC 4517 3.3.33. Telex Number</see>
    public static string ReadTelexNumber(ReadOnlySpan<byte> data) => Encoding.ASCII.GetString(data);

    /// <summary>Reads a UTC Time value.</summary>
    /// <remarks>
    /// While it is recommended for this value to be represented in UTF with the Z prefix it is not required. The
    /// output date time will be in the offset that was in the string rather than always UTC. This ensures no data is
    /// lost in translation but UTC can still be generated with <c>.ToUniversalTime()</c>.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTC Time' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The DateTimeOffset of the UTC time.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.34">RFC 4517 3.3.34. UTC Time</see>
    public static DateTimeOffset ReadUTCTime(ReadOnlySpan<byte> data)
    {
        ReadOnlySpan<char> value = Encoding.ASCII.GetString(data).AsSpan();
        int tzOffset = value.IndexOfAny(new[] { 'Z', '-', '+' });
        ReadOnlySpan<char> tzValue = value[tzOffset..];
        value = value[..tzOffset];

        int year = int.Parse(value[0..4]);
        int month = int.Parse(value[4..6]);
        int day = int.Parse(value[6..8]);
        int hour = int.Parse(value[8..10]);
        int minute = int.Parse(value[10..12]);
        int second = 0;

        value = value[12..];
        if (value.Length > 0)
            second = int.Parse(value[..2]);

        TimeSpan tz;
        if (tzValue.ToString() == "Z")
        {
            tz = TimeSpan.Zero;
        }
        else
        {
            int tzHour = int.Parse(tzValue[1..3]);
            int tzMinute = 0;
            if (tzValue.Length > 3)
                tzMinute = int.Parse(tzValue[3..5]);

            tz = new TimeSpan(tzHour, tzMinute, 0);
            if (tzValue[0] == '-')
                tz = -tz;
        }

        return new DateTimeOffset(year, month, day, hour, minute, second, tz);
    }

    /// <summary>Reads an LDAP Syntax Description.</summary>
    /// <remarks>
    /// This just returns the raw string value rather than process it into an object.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The parsed LDAP Syntax Description in the ABNF notation.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.18">RFC 4517 3.3.18. LDAP Syntax Description</see>
    public static string ReadLDAPSyntaxDescription(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);

    /// <summary>Reads a Substring Assertion.</summary>
    /// <remarks>
    /// The first index represents the initial value or <c>""</c> if not set, the last value represents the final value
    /// or <c>""</c> if not set. Any remaining values in the middle are the middle substring assertions.
    /// The LDAP definition for this syntax is:
    ///     ( 1.3.6.1.4.1.1466.115.121.1.58 DESC 'Substring Assertion' )
    /// </remarks>
    /// <param name="data">The raw byte value to read</param>
    /// <returns>The substring assertion values.</returns>
    /// <see href="https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.30">RFC 4517 3.3.30. Substring Assertion</see>
    public static string[] ReadSubstringAssertion(ReadOnlySpan<byte> data)
    {
        string value = Encoding.UTF8.GetString(data);

        return value.Split('*').Select(v => v.Replace("\\2A", "*").Replace("\\5C", "\\")).ToArray();
    }
}

/// <summary>A Teletex Terminal Identifier.</summary>
/// <remarks>
/// The ABNF notation of this field is:
///     teletex-id = ttx-term *(DOLLAR ttx-param)
///     ttx-term   = PrintableString          ; terminal identifier
///     ttx-param  = ttx-key COLON ttx-value  ; parameter
///     ttx-key    = "graphic" / "control" / "misc" / "page" / "private"
///     ttx-value  = *ttx-value-octet
///
///     ttx-value-octet = %x00-23
///                     / (%x5C "24")  ; escaped "$"
///                     / %x25-5B
///                     / (%x5C "5C")  ; escaped "\"
///                     / %x5D-FF
/// The LDAP definition for this syntax is:
///     ( 1.3.6.1.4.1.1466.115.121.1.51 DESC 'Teletex Terminal Identifier' )
/// </remarks>
public class TeletexTerminalIdentifier
{
    /// <summary>Teletex Terminal Identifier.</summary>
    public string Identifier { get; }

    /// <summary>Array of optional parameters for the identifier.</summary>
    public TeletexTerminalParameter[] Parameters { get; }

    public TeletexTerminalIdentifier(ReadOnlySpan<byte> data)
    {
        int dollarIdx = data.IndexOf((byte)0x24); // $
        List<TeletexTerminalParameter> parameters = new();

        if (dollarIdx == -1)
        {
            Identifier = Encoding.ASCII.GetString(data);
        }
        else
        {
            Identifier = Encoding.ASCII.GetString(data.Slice(0, dollarIdx));
            data = data[(dollarIdx + 1)..];

            while (data.Length > 0)
            {
                parameters.Add(TeletexTerminalParameter.ParseParameter(data, out var read));
                data = data[read..];
            }
        }

        Parameters = parameters.ToArray();
    }
}

/// <summary>Encoded form of a Teletex Terminal Identifier parameter.</summary>
public class TeletexTerminalParameter
{
    /// <summary>The name/key of the parameter.</summary>
    public string Name { get; }

    /// <summary>The raw bytes of the parameter.</summary>
    public byte[] Value { get; }

    public TeletexTerminalParameter(string name, byte[] value)
    {
        Name = name;
        Value = value;
    }

    /// <summary>Parse a Teletex Terminal Identifier parameter from the raw bytes.</summary>
    /// <param name="data">The raw bytes to start parsing from.</param>
    /// <oaram name="read">How many bytes that were consumed for this parameter.</param>
    /// <returns>The parsed Teletex Terminal Identifier parameter.</returns>
    internal static TeletexTerminalParameter ParseParameter(ReadOnlySpan<byte> data, out int read)
    {
        int colonIdx = data.IndexOf((byte)0x3A); // :
        string name = Encoding.ASCII.GetString(data.Slice(0, colonIdx));

        // The serialized form is going to be the same size or larger (if $ or \ are escaped). Keep the count to know
        // how much data was written after it was converted from the escaped form.
        Memory<byte> value = new Memory<byte>(new byte[data.Length - colonIdx]);
        Span<byte> encodedValue = value.Span;
        int count = 0;

        for (read = colonIdx + 1; read < data.Length; read++)
        {
            char c = (char)data[read];

            // Need to escape \24 or \5C is found.
            if (c == '\\' && data.Length > (read + 2))
            {
                string escapedHex = Encoding.ASCII.GetString(data.Slice(read + 1, 2));
                encodedValue[count] = Convert.ToByte(escapedHex, 16);
                count++;
                read += 2;
                continue;
            }
            else if (c == '$')
            {
                // Include the $ so the next call starts with what comes after $
                read++;
                break;
            }

            encodedValue[count] = data[read];
            count++;
        }

        return new TeletexTerminalParameter(name, value[..count].ToArray());
    }
}
