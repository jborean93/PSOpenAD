using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Linq;
using System.Numerics;
using System.Text;
using TUnit.Core;

namespace PSOpenADTests;

public class SyntaxDefinitionTests
{
    [Test]
    public async Task ReadAttributeTypeDescription()
    {
        const string raw = "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        var actual = SyntaxDefinition.ReadAttributeTypeDescription(data);

        await Assert.That(actual.OID).IsEqualTo("2.5.18.1");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "createTimestamp" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.SuperType).IsNull();
        await Assert.That(actual.Equality).IsEqualTo("generalizedTimeMatch");
        await Assert.That(actual.Ordering).IsEqualTo("generalizedTimeOrderingMatch");
        await Assert.That(actual.Substrings).IsNull();
        await Assert.That(actual.Syntax).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.24");
        await Assert.That(actual.SyntaxLength).IsNull();
        await Assert.That(actual.SingleValue).IsTrue();
        await Assert.That(actual.Collective).IsFalse();
        await Assert.That(actual.NoUserModification).IsTrue();
        await Assert.That(actual.Usage).IsEqualTo(AttributeTypeUsage.DirectoryOperation);
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("'0'B", new byte[] { 0 })]
    [Arguments("'1'B", new byte[] { 1 })]
    [Arguments("'11'B", new byte[] { 3 })]
    [Arguments("'00000101'B", new byte[] { 5 })]
    [Arguments("'0101111101'B", new byte[] { 1, 125 })]
    [Arguments("'1101000100011010'B", new byte[] { 209, 26 })]
    public async Task ReadBitString(string value, byte[] expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        byte[] actual = SyntaxDefinition.ReadBitString(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("TRUE", true)]
    [Arguments("FALSE", false)]
    public async Task ReadBoolean(string value, bool expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        bool actual = SyntaxDefinition.ReadBoolean(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("US", "US")]
    [Arguments("AU", "AU")]
    public async Task ReadCountryString(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadCountryString(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("CN=container", "CN=container")]
    [Arguments("OU=Users,DC=domain", "OU=Users,DC=domain")]
    public async Task ReadDN(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadDN(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("method1", new[] { "method1" })]
    [Arguments("method1 $ method2", new[] { "method1", "method2" })]
    public async Task ReadDeliveryMethod(string value, string[] expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string[] actual = SyntaxDefinition.ReadDeliveryMethod(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("Example Directory String", "Example Directory String")]
    [Arguments("Another 1", "Another 1")]
    public async Task ReadDirectoryString(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadDirectoryString(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ReadDITContentRuleDescription()
    {
        const string raw = "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        DITContentRuleDescription actual = SyntaxDefinition.ReadDITContentRuleDescription(data);

        await Assert.That(actual.OID).IsEqualTo("2.5.6.4");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsEqualTo("content rule for organization");
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Auxiliary).IsEmpty();
        await Assert.That(actual.Must).IsEmpty();
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Not).IsEquivalentTo(new[] { "x121Address", "telexNumber" });
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(raw);
    }

    [Test]
    public async Task ReadDITStructureRuleDescription()
    {
        const string raw = "( 2 DESC 'organization structure rule' FORM 2.5.15.3 )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        DITStructureRuleDescription actual = SyntaxDefinition.ReadDITStructureRuleDescription(data);

        await Assert.That(actual.Id).IsEqualTo("2");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsEqualTo("organization structure rule");
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Form).IsEqualTo("2.5.15.3");
        await Assert.That(actual.SuperRules).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(raw);
    }

    [Test]
    public async Task ReadEnhancedGuide()
    {
        const string raw = "person#(sn$EQ)#oneLevel";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadEnhancedGuide(data);

        await Assert.That(actual).IsEqualTo(raw);
    }

    [Test]
    [Arguments("12345678", "12345678")]
    [Arguments("12345678 $ twoDimensional", "12345678 $ twoDimensional")]
    public async Task ReadFacsimileTelephoneNumber(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadFacsimileTelephoneNumber(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments(new byte[] { 0 }, new byte[] { 0 })]
    [Arguments(new byte[] { 0, 2 }, new byte[] { 0, 2 })]
    public async Task ReadFax(byte[] value, byte[] expected)
    {
        byte[] actual = SyntaxDefinition.ReadFax(value);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    // In RFC 4517 as an example
    [Arguments("199412161032Z", 1994, 12, 16, 10, 32, 0, 0, 0)]
    [Arguments("199412160532-0500", 1994, 12, 16, 5, 32, 0, 0, -180000000000)]

    // Leap second cases
    [Arguments("20221231235860Z", 2022, 12, 31, 23, 59, 0, 0, 0)]
    [Arguments("20221231235960Z", 2023, 1, 1, 0, 0, 0, 0, 0)]

    // Permutations of date up hour
    [Arguments("2022010523Z", 2022, 1, 5, 23, 0, 0, 0, 0)]
    [Arguments("2022010523.0Z", 2022, 1, 5, 23, 0, 0, 0, 0)]
    [Arguments("2022010523.00Z", 2022, 1, 5, 23, 0, 0, 0, 0)]
    [Arguments("2022010523.5Z", 2022, 1, 5, 11, 30, 0, 0, 0)]
    [Arguments("2022010523.567Z", 2022, 1, 5, 13, 2, 27, 5999999, 0)]
    [Arguments("2022010523.567+10", 2022, 1, 5, 13, 2, 27, 5999999, 360000000000)]
    [Arguments("2022010523.567-10", 2022, 1, 5, 13, 2, 27, 5999999, -360000000000)]
    [Arguments("2022010523.567+1000", 2022, 1, 5, 13, 2, 27, 5999999, 360000000000)]
    [Arguments("2022010523.567-1000", 2022, 1, 5, 13, 2, 27, 5999999, -360000000000)]
    [Arguments("2022010523.567+1043", 2022, 1, 5, 13, 2, 27, 5999999, 385800000000)]
    [Arguments("2022010523.567-1043", 2022, 1, 5, 13, 2, 27, 5999999, -385800000000)]

    // Permutations of date up to minute
    [Arguments("202201052354Z", 2022, 1, 5, 23, 54, 0, 0, 0)]
    [Arguments("202201052354.0Z", 2022, 1, 5, 23, 54, 0, 0, 0)]
    [Arguments("202201052354.00Z", 2022, 1, 5, 23, 54, 0, 0, 0)]
    [Arguments("202201052354.5Z", 2022, 1, 5, 23, 27, 0, 0, 0)]
    [Arguments("202201052354.1928Z", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [Arguments("202201052354.1928+00", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [Arguments("202201052354.1928-00", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [Arguments("202201052354.1928+0000", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [Arguments("202201052354.1928-0000", 2022, 1, 5, 23, 10, 24, 6720000, 0)]

    // Permutations of date up to second
    [Arguments("20220105235432Z", 2022, 1, 5, 23, 54, 32, 0, 0)]
    [Arguments("20220105235432.0Z", 2022, 1, 5, 23, 54, 32, 0, 0)]
    [Arguments("20220105235432.00Z", 2022, 1, 5, 23, 54, 32, 0, 0)]
    [Arguments("20220105235432.1Z", 2022, 1, 5, 23, 54, 3, 2000000, 0)]
    [Arguments("20220105235432.0032Z", 2022, 1, 5, 23, 54, 0, 1024000, 0)]
    public async Task ReadGeneralizedTime(string value, int year, int month, int day, int hour, int minute, int second,
        long ticks, long tzOffset)
    {
        DateTimeOffset expected = new(year, month, day, hour, minute, second, new TimeSpan(tzOffset));
        expected = expected.AddTicks(ticks);
        byte[] data = Encoding.UTF8.GetBytes(value);

        DateTimeOffset actual = SyntaxDefinition.ReadGeneralizedTime(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("oid criteria", "oid criteria")]
    [Arguments("criteria", "criteria")]
    public async Task ReadGuide(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadGuide(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("<test 123>", "<test 123>")]
    [Arguments("café", "caf??")]
    public async Task ReadIA5String(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadIA5String(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("0")]
    [Arguments("-0")]
    [Arguments("1")]
    [Arguments("-1")]
    [Arguments("9223372036854775808")]
    [Arguments("-9223372036854775809")]
    public async Task ReadInteger(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);
        BigInteger expected = BigInteger.Parse(value);

        BigInteger actual = SyntaxDefinition.ReadInteger(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments(new byte[] { 0 }, new byte[] { 0 })]
    [Arguments(new byte[] { 0, 2 }, new byte[] { 0, 2 })]
    public async Task ReadJPEG(byte[] value, byte[] expected)
    {
        byte[] actual = SyntaxDefinition.ReadJPEG(value);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ReadMatchingRuleDescription()
    {
        const string raw = "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        MatchingRuleDescription actual = SyntaxDefinition.ReadMatchingRuleDescription(data);

        await Assert.That(actual.OID).IsEqualTo("2.5.13.2");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "caseIgnoreMatch" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Syntax).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.15");
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(raw);
    }

    [Test]
    public async Task ReadMatchingRuleUseDescription()
    {
        const string raw = "( 2.5.13.16 APPLIES ( givenName $ surname ) )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        MatchingRuleUseDescription actual = SyntaxDefinition.ReadMatchingRuleUseDescription(data);

        await Assert.That(actual.OID).IsEqualTo("2.5.13.16");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Applies).IsEquivalentTo(new [] { "givenName", "surname" });
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(raw);
    }

    [Test]
    [Arguments("1.3.6.1.4.1.1466.0")]
    [Arguments("1.3.6.1.4.1.1466.0#'0101'B")]
    [Arguments("1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB")]
    [Arguments("1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB#'0101'B")]
    public async Task ReadNameAndOptionalUID(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadNameAndOptionalUID(data);

        await Assert.That(actual).IsEqualTo(value);
    }

    [Test]
    public async Task ReadNameFormDescription()
    {
        const string raw = "( 2.5.15.3 NAME 'orgNameForm' OC organization MUST o )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        NameFormDescription actual = SyntaxDefinition.ReadNameFormDescription(data);

        await Assert.That(actual.OID).IsEqualTo("2.5.15.3");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "orgNameForm" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.ObjectClass).IsEqualTo("organization");
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "o" });
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(raw);
    }

    [Test]
    [Arguments("0", new[] { "0" })]
    [Arguments("1", new[] { "1" })]
    [Arguments("9223372036854775808 123    0", new[] { "9223372036854775808", "123", "0" })]
    public async Task ReadNumericString(string value, string[] expectedValues)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);
        BigInteger[] expected = expectedValues.Select(v => BigInteger.Parse(v)).ToArray();

        BigInteger[] actual = SyntaxDefinition.ReadNumericString(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ReadObjectClassDescription()
    {
        const string raw = "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        ObjectClassDescription actual = SyntaxDefinition.ReadObjectClassDescription(data);

        await Assert.That(actual.OID).IsEqualTo("2.5.6.2");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "country" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.SuperTypes).IsEquivalentTo(new[] { "top" });
        await Assert.That(actual.Kind).IsEqualTo(ObjectClassKind.Structural);
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "c" });
        await Assert.That(actual.May).IsEquivalentTo(new[] { "searchGuide", "description" });
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(raw);
    }

    [Test]
    [Arguments("1.2.3.4")]
    [Arguments("cn")]
    public async Task ReadOID(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadOID(data);

        await Assert.That(actual).IsEqualTo(value);
    }

    [Test]
    [Arguments("MCIMail $ testing")]
    [Arguments("MailboxType $ My Mailbox")]
    public async Task ReadOtherMailbox(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadOID(data);

        await Assert.That(actual).IsEqualTo(value);
    }

    [Test]
    [Arguments(new byte[] { 0 }, new byte[] { 0 })]
    [Arguments(new byte[] { 0, 2 }, new byte[] { 0, 2 })]
    public async Task ReadOctetString(byte[] value, byte[] expected)
    {
        byte[] actual = SyntaxDefinition.ReadOctetString(value);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ReadPostalAddress()
    {
        const string ADDRESS = "1234 Main St.$Anytown, CA 12345$$USA\\241,000,000\\5CnSweepstakes$PO Box 1000000$Anytown, CA 12345$USA";
        byte[] data = Encoding.UTF8.GetBytes(ADDRESS);
        string[] expected = new[] {
            "1234 Main St.",
            "Anytown, CA 12345",
            "",
            "USA$1,000,000\\nSweepstakes",
            "PO Box 1000000",
            "Anytown, CA 12345",
            "USA"
        };

        string[] actual = SyntaxDefinition.ReadPostalAddress(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("<test 123>", "<test 123>")]
    [Arguments("café", "caf??")]
    public async Task ReadPresentationAddress(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadPresentationAddress(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("<test 123>", "<test 123>")]
    [Arguments("café", "caf??")]
    public async Task ReadPrintableString(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadPrintableString(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("+1 512 315 0280")]
    [Arguments("+1-512-315-0280")]
    [Arguments("+61 3 9896 7830")]
    public async Task ReadTelephoneNumber(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadTelephoneNumber(data);

        await Assert.That(actual).IsEqualTo(value);
    }

    [Test]
    public async Task ReadTeletexTerminalIdentifierNoParameters()
    {
        const string TTI = "testing.123-456";
        byte[] data = Encoding.ASCII.GetBytes(TTI);

        TeletexTerminalIdentifier actual = SyntaxDefinition.ReadTeletexTerminalIdentifier(data);

        await Assert.That(actual.Identifier).IsEqualTo("testing.123-456");
        await Assert.That(actual.Parameters).IsEmpty();
    }

    [Test]
    public async Task ReadTeletexTerminalIdentifierWithParameters()
    {
        const string TTI = "testing.123:456$graphic:testing \\5C\\24 \\24\\5C$control:$private:";
        int ttiByteCount = Encoding.UTF8.GetByteCount(TTI);

        byte[] data = new byte[ttiByteCount + 3];
        Encoding.UTF8.GetBytes(TTI, 0, TTI.Length, data, 0);
        data[ttiByteCount] = (byte)0;
        data[ttiByteCount + 1] = (byte)1;
        data[ttiByteCount + 2] = (byte)255;

        TeletexTerminalIdentifier actual = SyntaxDefinition.ReadTeletexTerminalIdentifier(data);

        await Assert.That(actual.Identifier).IsEqualTo("testing.123:456");
        await Assert.That(actual.Parameters.Length).IsEqualTo(3);

        TeletexTerminalParameter param = actual.Parameters[0];
        await Assert.That(param.Name).IsEqualTo("graphic");
        await Assert.That(param.Value).IsEquivalentTo(Encoding.UTF8.GetBytes("testing \\$ $\\"));

        param = actual.Parameters[1];
        await Assert.That(param.Name).IsEqualTo("control");
        await Assert.That(param.Value).IsEmpty();

        param = actual.Parameters[2];
        await Assert.That(param.Name).IsEqualTo("private");
        await Assert.That(param.Value).IsEquivalentTo(new byte[] { 0, 1, 255 });
    }

    [Test]
    public async Task ReadTelexNumber()
    {
        const string raw = "actual-number$country-code$answerback";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadTelexNumber(data);

        await Assert.That(actual).IsEqualTo(raw);
    }

    [Test]
    [Arguments("199412161032Z", 1994, 12, 16, 10, 32, 0, 0)]
    [Arguments("199412160532-0500", 1994, 12, 16, 5, 32, 0, -180000000000)]
    [Arguments("202201052354Z", 2022, 1, 5, 23, 54, 0, 0)]
    [Arguments("202201052354+00", 2022, 1, 5, 23, 54, 0, 0)]
    [Arguments("202201052354-00", 2022, 1, 5, 23, 54, 0, 0)]
    [Arguments("202201052354+0000", 2022, 1, 5, 23, 54, 0, 0)]
    [Arguments("202201052354-0000", 2022, 1, 5, 23, 54, 0, 0)]
    [Arguments("202201052354+10", 2022, 1, 5, 23, 54, 0, 360000000000)]
    [Arguments("202201052354-10", 2022, 1, 5, 23, 54, 0, -360000000000)]
    [Arguments("202201052354+1000", 2022, 1, 5, 23, 54, 0, 360000000000)]
    [Arguments("202201052354-1000", 2022, 1, 5, 23, 54, 0, -360000000000)]
    [Arguments("202201052354+1043", 2022, 1, 5, 23, 54, 0, 385800000000)]
    [Arguments("202201052354-1043", 2022, 1, 5, 23, 54, 0, -385800000000)]

    [Arguments("20220105235401Z", 2022, 1, 5, 23, 54, 1, 0)]
    [Arguments("20220105235401+00", 2022, 1, 5, 23, 54, 1, 0)]
    [Arguments("20220105235401-00", 2022, 1, 5, 23, 54, 1, 0)]
    [Arguments("20220105235401+0000", 2022, 1, 5, 23, 54, 1, 0)]
    [Arguments("20220105235401-0000", 2022, 1, 5, 23, 54, 1, 0)]
    [Arguments("20220105235401+10", 2022, 1, 5, 23, 54, 1, 360000000000)]
    [Arguments("20220105235401-10", 2022, 1, 5, 23, 54, 1, -360000000000)]
    [Arguments("20220105235401+1000", 2022, 1, 5, 23, 54, 1, 360000000000)]
    [Arguments("20220105235401-1000", 2022, 1, 5, 23, 54, 1, -360000000000)]
    [Arguments("20220105235401+1043", 2022, 1, 5, 23, 54, 1, 385800000000)]
    [Arguments("20220105235401-1043", 2022, 1, 5, 23, 54, 1, -385800000000)]
    public async Task ReadUTCTime(string value, int year, int month, int day, int hour, int minute, int second,
        long tzOffset)
    {
        DateTimeOffset expected = new(year, month, day, hour, minute, second, new TimeSpan(tzOffset));
        byte[] data = Encoding.UTF8.GetBytes(value);

        DateTimeOffset actual = SyntaxDefinition.ReadUTCTime(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ReadLDAPSyntaxDescription()
    {
        const string raw = "( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        SyntaxDescription actual = SyntaxDefinition.ReadLDAPSyntaxDescription(data);

        await Assert.That(actual.OID).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.54");
        await Assert.That(actual.Description).IsEqualTo("LDAP Syntax Description");
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(raw);
    }

    [Test]
    [Arguments("*", new[] { "", "" })]
    [Arguments("*abc*", new[] { "", "abc", "" })]
    [Arguments("*abc*def*", new[] { "", "abc", "def", "" })]
    [Arguments("abc*", new[] { "abc", "" })]
    [Arguments("abc*def*", new[] { "abc", "def", "" })]
    [Arguments("*abc", new[] { "", "abc" })]
    [Arguments("*abc*def", new[] { "", "abc", "def" })]
    [Arguments("abc*def*ghi", new[] { "abc", "def", "ghi" })]
    [Arguments("abc\\2A*\\2Adef\\5C2A*ghi*\\5C\\2Ajkl", new[] { "abc*", "*def\\2A", "ghi", "\\*jkl" })]
    public async Task ReadSubstringAssertion(string value, string[] expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string[] actual = SyntaxDefinition.ReadSubstringAssertion(data);

        await Assert.That(actual).IsEquivalentTo(expected);
    }
}
