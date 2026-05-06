using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using TUnit.Core;

namespace PSOpenADTests;

public class AttributeTypeDescriptionTests
{
    [Test]
    public async Task ParseAttributeDescription()
    {
        const string VALUE = "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )";

        var actual = new AttributeTypeDescription(VALUE);

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

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithExtensions()
    {
        const string VALUE = "( 0.9.2342.19200300.100.1.1 NAME 'uid' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} X-ORIGIN 'RFC 1274' )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
        };

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("0.9.2342.19200300.100.1.1");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "uid" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.SuperType).IsNull();
        await Assert.That(actual.Equality).IsEqualTo("caseIgnoreMatch");
        await Assert.That(actual.Ordering).IsNull();
        await Assert.That(actual.Substrings).IsEqualTo("caseIgnoreSubstringsMatch");
        await Assert.That(actual.Syntax).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.15");
        await Assert.That(actual.SyntaxLength).IsEqualTo(256);
        await Assert.That(actual.SingleValue).IsFalse();
        await Assert.That(actual.Collective).IsFalse();
        await Assert.That(actual.NoUserModification).IsFalse();
        await Assert.That(actual.Usage).IsEqualTo(AttributeTypeUsage.UserApplications);
        await Assert.That(actual.Extensions).IsEquivalentTo(expectedExtensions);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseADSyntaxOID()
    {
        const string VALUE = "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' SINGLE-VALUE )";
        const string EXPECTED_STR = "( 1.2.840.113556.1.4.221 NAME 'sAMAccountName' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.2.840.113556.1.4.221");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "sAMAccountName" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.SuperType).IsNull();
        await Assert.That(actual.Equality).IsNull();
        await Assert.That(actual.Ordering).IsNull();
        await Assert.That(actual.Substrings).IsNull();
        await Assert.That(actual.Syntax).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.15");
        await Assert.That(actual.SyntaxLength).IsNull();
        await Assert.That(actual.SingleValue).IsTrue();
        await Assert.That(actual.Collective).IsFalse();
        await Assert.That(actual.NoUserModification).IsFalse();
        await Assert.That(actual.Usage).IsEqualTo(AttributeTypeUsage.UserApplications);
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseADSyntaxDesc()
    {
        const string VALUE = "( 1.2.840.113556.1.2.83 NAME 'repsTo' SYNTAX 'OctetString' NO-USER-MODIFICATION )";
        const string EXPECTED_STR = "( 1.2.840.113556.1.2.83 NAME 'repsTo' SYNTAX OctetString NO-USER-MODIFICATION )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.2.840.113556.1.2.83");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "repsTo" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.SuperType).IsNull();
        await Assert.That(actual.Equality).IsNull();
        await Assert.That(actual.Ordering).IsNull();
        await Assert.That(actual.Substrings).IsNull();
        await Assert.That(actual.Syntax).IsEqualTo("OctetString");
        await Assert.That(actual.SyntaxLength).IsNull();
        await Assert.That(actual.SingleValue).IsFalse();
        await Assert.That(actual.Collective).IsFalse();
        await Assert.That(actual.NoUserModification).IsTrue();
        await Assert.That(actual.Usage).IsEqualTo(AttributeTypeUsage.UserApplications);
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseWithNoNames()
    {
        const string VALUE = "( 1.0 )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEmpty();

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "name1", "name2" });

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 NAME ( 'name1' 'name2' ) )");
    }

    [Test]
    public async Task ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Description).IsEqualTo("foo 'bar'");

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 DESC 'foo \\27bar\\27' )");
    }

    [Test]
    public async Task ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Obsolete).IsTrue();

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 OBSOLETE )");
    }

    [Test]
    public async Task ParseWithSuperType()
    {
        const string VALUE = "( 1.0 SUP 1.2.34  )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.SuperType).IsEqualTo("1.2.34");

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 SUP 1.2.34 )");
    }

    [Test]
    public async Task ParseWithCollective()
    {
        const string VALUE = "( 1.0 COLLECTIVE   )";

        var actual = new AttributeTypeDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Collective).IsTrue();

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 COLLECTIVE )");
    }

    [Test]
    [Arguments("userApplications", AttributeTypeUsage.UserApplications)]
    [Arguments("directoryOperation", AttributeTypeUsage.DirectoryOperation)]
    [Arguments("distributedOperation", AttributeTypeUsage.DistributedOperation)]
    [Arguments("dSAOperation", AttributeTypeUsage.DsaOperation)]
    public async Task ParseWithUsage(string usage, AttributeTypeUsage expected)
    {
        string value = $"( 1.0 USAGE {usage} )";

        var actual = new AttributeTypeDescription(value);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Usage).IsEqualTo(expected);

        if (usage == "userApplications")
        {
            await Assert.That(actual.ToString()).IsEqualTo("( 1.0 )");
        }
        else
        {
            await Assert.That(actual.ToString()).IsEqualTo($"( 1.0 USAGE {usage} )");
        }
    }

    [Test]
    public async Task ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = await Assert.That(() => new AttributeTypeDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid AttributeTypeDescription value does not start with '('");
    }

    [Test]
    public async Task ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = await Assert.That(() => new AttributeTypeDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid AttributeTypeDescription value does not end with ')'");
    }

    [Test]
    public async Task NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = await Assert.That(() => new AttributeTypeDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid AttributeTypeDescription OID value is invalid");
    }

    [Test]
    public async Task UsageWithInvalidValue()
    {
        const string VALUE = "( 1.0 USAGE invalidValue )";

        var ex = await Assert.That(() => new AttributeTypeDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid AttributeTypeDescription USAGE value is invalid");
    }
}
