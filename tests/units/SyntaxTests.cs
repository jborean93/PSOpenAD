using PSOpenAD.LDAP;
using System;
using System.Linq;
using System.Numerics;
using System.Text;
using Xunit;

namespace PSOpenADTests;

public class SyntaxDefinitionTests
{
    [Fact]
    public void ReadAttributeTypeDescription()
    {
        const string raw = "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        var actual = SyntaxDefinition.ReadAttributeTypeDescription(data);

        Assert.Equal("2.5.18.1", actual.OID);
        Assert.Equal(new[] { "createTimestamp" }, actual.Names);
        Assert.Null(actual.Description);
        Assert.False(actual.Obsolete);
        Assert.Null(actual.SuperType);
        Assert.Equal("generalizedTimeMatch", actual.Equality);
        Assert.Equal("generalizedTimeOrderingMatch", actual.Ordering);
        Assert.Null(actual.Substrings);
        Assert.Equal("1.3.6.1.4.1.1466.115.121.1.24", actual.Syntax);
        Assert.Null(actual.SyntaxLength);
        Assert.True(actual.SingleValue);
        Assert.False(actual.Collective);
        Assert.True(actual.NoUserModification);
        Assert.Equal(AttributeTypeUsage.DirectoryOperation, actual.Usage);
        Assert.Empty(actual.Extensions);
    }

    [Theory]
    [InlineData("'0'B", new byte[] { 0 })]
    [InlineData("'1'B", new byte[] { 1 })]
    [InlineData("'11'B", new byte[] { 3 })]
    [InlineData("'00000101'B", new byte[] { 5 })]
    [InlineData("'0101111101'B", new byte[] { 1, 125 })]
    [InlineData("'1101000100011010'B", new byte[] { 209, 26 })]
    public void ReadBitString(string value, byte[] expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        byte[] actual = SyntaxDefinition.ReadBitString(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("TRUE", true)]
    [InlineData("FALSE", false)]
    public void ReadBoolean(string value, bool expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        bool actual = SyntaxDefinition.ReadBoolean(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("US", "US")]
    [InlineData("AU", "AU")]
    public void ReadCountryString(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadCountryString(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("CN=container", "CN=container")]
    [InlineData("OU=Users,DC=domain", "OU=Users,DC=domain")]
    public void ReadDN(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadDN(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("method1", new[] { "method1" })]
    [InlineData("method1 $ method2", new[] { "method1", "method2" })]
    public void ReadDeliveryMethod(string value, string[] expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string[] actual = SyntaxDefinition.ReadDeliveryMethod(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("Example Directory String", "Example Directory String")]
    [InlineData("Another 1", "Another 1")]
    public void ReadDirectoryString(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadDirectoryString(data);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ReadDITContextRuleDescription()
    {
        const string raw = "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadDITContentRuleDescription(data);

        Assert.Equal(raw, actual);
    }

    [Fact]
    public void ReadDITStructureRuleDescription()
    {
        const string raw = "( 2 DESC 'organization structure rule' FORM 2.5.15.3 )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadDITStructureRuleDescription(data);

        Assert.Equal(raw, actual);
    }

    [Fact]
    public void ReadEnhancedGuide()
    {
        const string raw = "person#(sn$EQ)#oneLevel";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadDITStructureRuleDescription(data);

        Assert.Equal(raw, actual);
    }

    [Theory]
    [InlineData("12345678", "12345678")]
    [InlineData("12345678 $ twoDimensional", "12345678 $ twoDimensional")]
    public void ReadFacsimileTelephoneNumber(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadFacsimileTelephoneNumber(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(new byte[] { 0 }, new byte[] { 0 })]
    [InlineData(new byte[] { 0, 2 }, new byte[] { 0, 2 })]
    public void ReadFax(byte[] value, byte[] expected)
    {
        byte[] actual = SyntaxDefinition.ReadFax(value);

        Assert.Equal(expected, actual);
    }

    [Theory]
    // In RFC 4517 as an example
    [InlineData("199412161032Z", 1994, 12, 16, 10, 32, 0, 0, 0)]
    [InlineData("199412160532-0500", 1994, 12, 16, 5, 32, 0, 0, -180000000000)]

    // Leap second cases
    [InlineData("20221231235860Z", 2022, 12, 31, 23, 59, 0, 0, 0)]
    [InlineData("20221231235960Z", 2023, 1, 1, 0, 0, 0, 0, 0)]

    // Permutations of date up hour
    [InlineData("2022010523Z", 2022, 1, 5, 23, 0, 0, 0, 0)]
    [InlineData("2022010523.0Z", 2022, 1, 5, 23, 0, 0, 0, 0)]
    [InlineData("2022010523.00Z", 2022, 1, 5, 23, 0, 0, 0, 0)]
    [InlineData("2022010523.5Z", 2022, 1, 5, 11, 30, 0, 0, 0)]
    [InlineData("2022010523.567Z", 2022, 1, 5, 13, 2, 27, 5999999, 0)]
    [InlineData("2022010523.567+10", 2022, 1, 5, 13, 2, 27, 5999999, 360000000000)]
    [InlineData("2022010523.567-10", 2022, 1, 5, 13, 2, 27, 5999999, -360000000000)]
    [InlineData("2022010523.567+1000", 2022, 1, 5, 13, 2, 27, 5999999, 360000000000)]
    [InlineData("2022010523.567-1000", 2022, 1, 5, 13, 2, 27, 5999999, -360000000000)]
    [InlineData("2022010523.567+1043", 2022, 1, 5, 13, 2, 27, 5999999, 385800000000)]
    [InlineData("2022010523.567-1043", 2022, 1, 5, 13, 2, 27, 5999999, -385800000000)]

    // Permutations of date up to minute
    [InlineData("202201052354Z", 2022, 1, 5, 23, 54, 0, 0, 0)]
    [InlineData("202201052354.0Z", 2022, 1, 5, 23, 54, 0, 0, 0)]
    [InlineData("202201052354.00Z", 2022, 1, 5, 23, 54, 0, 0, 0)]
    [InlineData("202201052354.5Z", 2022, 1, 5, 23, 27, 0, 0, 0)]
    [InlineData("202201052354.1928Z", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [InlineData("202201052354.1928+00", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [InlineData("202201052354.1928-00", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [InlineData("202201052354.1928+0000", 2022, 1, 5, 23, 10, 24, 6720000, 0)]
    [InlineData("202201052354.1928-0000", 2022, 1, 5, 23, 10, 24, 6720000, 0)]

    // Permutations of date up to second
    [InlineData("20220105235432Z", 2022, 1, 5, 23, 54, 32, 0, 0)]
    [InlineData("20220105235432.0Z", 2022, 1, 5, 23, 54, 32, 0, 0)]
    [InlineData("20220105235432.00Z", 2022, 1, 5, 23, 54, 32, 0, 0)]
    [InlineData("20220105235432.1Z", 2022, 1, 5, 23, 54, 3, 2000000, 0)]
    [InlineData("20220105235432.0032Z", 2022, 1, 5, 23, 54, 0, 1024000, 0)]
    public void ReadGeneralizedTime(string value, int year, int month, int day, int hour, int minute, int second,
        long ticks, long tzOffset)
    {
        DateTimeOffset expected = new(year, month, day, hour, minute, second, new TimeSpan(tzOffset));
        expected = expected.AddTicks(ticks);
        byte[] data = Encoding.UTF8.GetBytes(value);

        DateTimeOffset actual = SyntaxDefinition.ReadGeneralizedTime(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("oid criteria", "oid criteria")]
    [InlineData("criteria", "criteria")]
    public void ReadGuide(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadGuide(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("<test 123>", "<test 123>")]
    [InlineData("café", "caf??")]
    public void ReadIA5String(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadIA5String(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("-0")]
    [InlineData("1")]
    [InlineData("-1")]
    [InlineData("9223372036854775808")]
    [InlineData("-9223372036854775809")]
    public void ReadInteger(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);
        BigInteger expected = BigInteger.Parse(value);

        BigInteger actual = SyntaxDefinition.ReadInteger(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData(new byte[] { 0 }, new byte[] { 0 })]
    [InlineData(new byte[] { 0, 2 }, new byte[] { 0, 2 })]
    public void ReadJPEG(byte[] value, byte[] expected)
    {
        byte[] actual = SyntaxDefinition.ReadJPEG(value);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ReadMatchingRuleDescription()
    {
        const string raw = "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadMatchingRuleDescription(data);

        Assert.Equal(raw, actual);
    }

    [Fact]
    public void ReadMatchingRuleUseDescription()
    {
        const string raw = "( 2.5.13.16 APPLIES ( givenName $ surname ) )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadMatchingRuleUseDescription(data);

        Assert.Equal(raw, actual);
    }

    [Theory]
    [InlineData("1.3.6.1.4.1.1466.0")]
    [InlineData("1.3.6.1.4.1.1466.0#'0101'B")]
    [InlineData("1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB")]
    [InlineData("1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB#'0101'B")]
    public void ReadNameAndOptionalUID(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadNameAndOptionalUID(data);

        Assert.Equal(value, actual);
    }

    [Fact]
    public void ReadNameFormDescription()
    {
        const string raw = "( 2.5.15.3 NAME 'orgNameForm' OC organization MUST o )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadNameFormDescription(data);

        Assert.Equal(raw, actual);
    }

    [Theory]
    [InlineData("0", new[] { "0" })]
    [InlineData("1", new[] { "1" })]
    [InlineData("9223372036854775808 123    0", new[] { "9223372036854775808", "123", "0" })]
    public void ReadNumericString(string value, string[] expectedValues)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);
        BigInteger[] expected = expectedValues.Select(v => BigInteger.Parse(v)).ToArray();

        BigInteger[] actual = SyntaxDefinition.ReadNumericString(data);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ReadObjectClassDescription()
    {
        const string raw = "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadObjectClassDescription(data);

        Assert.Equal(raw, actual);
    }

    [Theory]
    [InlineData("1.2.3.4")]
    [InlineData("cn")]
    public void ReadOID(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadOID(data);

        Assert.Equal(value, actual);
    }

    [Theory]
    [InlineData("MCIMail $ testing")]
    [InlineData("MailboxType $ My Mailbox")]
    public void ReadOtherMailbox(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadOID(data);

        Assert.Equal(value, actual);
    }

    [Theory]
    [InlineData(new byte[] { 0 }, new byte[] { 0 })]
    [InlineData(new byte[] { 0, 2 }, new byte[] { 0, 2 })]
    public void ReadOctetString(byte[] value, byte[] expected)
    {
        byte[] actual = SyntaxDefinition.ReadOctetString(value);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ReadPostalAddress()
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

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("<test 123>", "<test 123>")]
    [InlineData("café", "caf??")]
    public void ReadPresentationAddress(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadPresentationAddress(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("<test 123>", "<test 123>")]
    [InlineData("café", "caf??")]
    public void ReadPrintableString(string value, string expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadPrintableString(data);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("+1 512 315 0280")]
    [InlineData("+1-512-315-0280")]
    [InlineData("+61 3 9896 7830")]
    public void ReadTelephoneNumber(string value)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string actual = SyntaxDefinition.ReadTelephoneNumber(data);

        Assert.Equal(value, actual);
    }

    [Fact]
    public void ReadTeletexTerminalIdentifierNoParameters()
    {
        const string TTI = "testing.123-456";
        byte[] data = Encoding.ASCII.GetBytes(TTI);

        TeletexTerminalIdentifier actual = SyntaxDefinition.ReadTeletexTerminalIdentifier(data);

        Assert.Equal("testing.123-456", actual.Identifier);
        Assert.Empty(actual.Parameters);
    }

    [Fact]
    public void ReadTeletexTerminalIdentifierWithParameters()
    {
        const string TTI = "testing.123:456$graphic:testing \\5C\\24 \\24\\5C$control:$private:";
        int ttiByteCount = Encoding.UTF8.GetByteCount(TTI);

        byte[] data = new byte[ttiByteCount + 3];
        Encoding.UTF8.GetBytes(TTI, 0, TTI.Length, data, 0);
        data[ttiByteCount] = (byte)0;
        data[ttiByteCount + 1] = (byte)1;
        data[ttiByteCount + 2] = (byte)255;

        TeletexTerminalIdentifier actual = SyntaxDefinition.ReadTeletexTerminalIdentifier(data);

        Assert.Equal("testing.123:456", actual.Identifier);
        Assert.Equal(3, actual.Parameters.Length);

        TeletexTerminalParameter param = actual.Parameters[0];
        Assert.Equal("graphic", param.Name);
        Assert.Equal(Encoding.UTF8.GetBytes("testing \\$ $\\"), param.Value);

        param = actual.Parameters[1];
        Assert.Equal("control", param.Name);
        Assert.Empty(param.Value);

        param = actual.Parameters[2];
        Assert.Equal("private", param.Name);
        Assert.Equal(new byte[] { 0, 1, 255 }, param.Value);
    }

    [Fact]
    public void ReadTelexNumber()
    {
        const string raw = "actual-number$country-code$answerback";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadTelexNumber(data);

        Assert.Equal(raw, actual);
    }

    [Theory]
    [InlineData("199412161032Z", 1994, 12, 16, 10, 32, 0, 0)]
    [InlineData("199412160532-0500", 1994, 12, 16, 5, 32, 0, -180000000000)]
    [InlineData("202201052354Z", 2022, 1, 5, 23, 54, 0, 0)]
    [InlineData("202201052354+00", 2022, 1, 5, 23, 54, 0, 0)]
    [InlineData("202201052354-00", 2022, 1, 5, 23, 54, 0, 0)]
    [InlineData("202201052354+0000", 2022, 1, 5, 23, 54, 0, 0)]
    [InlineData("202201052354-0000", 2022, 1, 5, 23, 54, 0, 0)]
    [InlineData("202201052354+10", 2022, 1, 5, 23, 54, 0, 360000000000)]
    [InlineData("202201052354-10", 2022, 1, 5, 23, 54, 0, -360000000000)]
    [InlineData("202201052354+1000", 2022, 1, 5, 23, 54, 0, 360000000000)]
    [InlineData("202201052354-1000", 2022, 1, 5, 23, 54, 0, -360000000000)]
    [InlineData("202201052354+1043", 2022, 1, 5, 23, 54, 0, 385800000000)]
    [InlineData("202201052354-1043", 2022, 1, 5, 23, 54, 0, -385800000000)]

    [InlineData("20220105235401Z", 2022, 1, 5, 23, 54, 1, 0)]
    [InlineData("20220105235401+00", 2022, 1, 5, 23, 54, 1, 0)]
    [InlineData("20220105235401-00", 2022, 1, 5, 23, 54, 1, 0)]
    [InlineData("20220105235401+0000", 2022, 1, 5, 23, 54, 1, 0)]
    [InlineData("20220105235401-0000", 2022, 1, 5, 23, 54, 1, 0)]
    [InlineData("20220105235401+10", 2022, 1, 5, 23, 54, 1, 360000000000)]
    [InlineData("20220105235401-10", 2022, 1, 5, 23, 54, 1, -360000000000)]
    [InlineData("20220105235401+1000", 2022, 1, 5, 23, 54, 1, 360000000000)]
    [InlineData("20220105235401-1000", 2022, 1, 5, 23, 54, 1, -360000000000)]
    [InlineData("20220105235401+1043", 2022, 1, 5, 23, 54, 1, 385800000000)]
    [InlineData("20220105235401-1043", 2022, 1, 5, 23, 54, 1, -385800000000)]
    public void ReadUTCTime(string value, int year, int month, int day, int hour, int minute, int second,
        long tzOffset)
    {
        DateTimeOffset expected = new(year, month, day, hour, minute, second, new TimeSpan(tzOffset));
        byte[] data = Encoding.UTF8.GetBytes(value);

        DateTimeOffset actual = SyntaxDefinition.ReadUTCTime(data);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ReadLDAPSyntaxDescription()
    {
        const string raw = "( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )";
        byte[] data = Encoding.UTF8.GetBytes(raw);

        string actual = SyntaxDefinition.ReadLDAPSyntaxDescription(data);

        Assert.Equal(raw, actual);
    }

    [Theory]
    [InlineData("*", new[] { "", "" })]
    [InlineData("*abc*", new[] { "", "abc", "" })]
    [InlineData("*abc*def*", new[] { "", "abc", "def", "" })]
    [InlineData("abc*", new[] { "abc", "" })]
    [InlineData("abc*def*", new[] { "abc", "def", "" })]
    [InlineData("*abc", new[] { "", "abc" })]
    [InlineData("*abc*def", new[] { "", "abc", "def" })]
    [InlineData("abc*def*ghi", new[] { "abc", "def", "ghi" })]
    [InlineData("abc\\2A*\\2Adef\\5C2A*ghi*\\5C\\2Ajkl", new[] { "abc*", "*def\\2A", "ghi", "\\*jkl" })]
    public void ReadSubstringAssertion(string value, string[] expected)
    {
        byte[] data = Encoding.UTF8.GetBytes(value);

        string[] actual = SyntaxDefinition.ReadSubstringAssertion(data);

        Assert.Equal(expected, actual);
    }
}
