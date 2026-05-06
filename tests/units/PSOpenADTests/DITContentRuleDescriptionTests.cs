using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using TUnit.Core;

namespace PSOpenADTests;

public class DITContentRuleDescriptionTests
{
    [Test]
    public async Task ParseDITContentRuleDescription()
    {
        const string VALUE = "( 2.5.6.4 DESC 'content rule for organization' NOT ( x121Address $ telexNumber ) )";

        var actual = new DITContentRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.6.4");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsEqualTo("content rule for organization");
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Auxiliary).IsEmpty();
        await Assert.That(actual.Must).IsEmpty();
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Not).IsEquivalentTo(new[] { "x121Address", "telexNumber" });
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseDITContentRuleDescriptionAD()
    {
        const string VALUE = "( 1.2.840.113556.1.5.282 NAME 'msDS-GroupManagedServiceAccount' AUX ( mailRecipient $ posixGroup $ ipHost ) MUST (objectSid $ sAMAccountName ) MAY (info $ garbageCollPeriod$ msExchAssistantName ))";
        const string EXPECTED_STR = "( 1.2.840.113556.1.5.282 NAME 'msDS-GroupManagedServiceAccount' AUX ( mailRecipient $ posixGroup $ ipHost ) MUST ( objectSid $ sAMAccountName ) MAY ( info $ garbageCollPeriod $ msExchAssistantName ) )";

        var actual = new DITContentRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.2.840.113556.1.5.282");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "msDS-GroupManagedServiceAccount" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Auxiliary).IsEquivalentTo(new[] { "mailRecipient", "posixGroup", "ipHost" });
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "objectSid", "sAMAccountName" });
        await Assert.That(actual.May).IsEquivalentTo(new[] { "info", "garbageCollPeriod", "msExchAssistantName" });
        await Assert.That(actual.Not).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseNoOptional()
    {
        const string VALUE = "( 1.0 )";

        var actual = new DITContentRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Auxiliary).IsEmpty();
        await Assert.That(actual.Must).IsEmpty();
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Not).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithExtensions()
    {
        const string VALUE = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new DITContentRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Auxiliary).IsEmpty();
        await Assert.That(actual.Must).IsEmpty();
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Not).IsEmpty();
        await Assert.That(actual.Extensions).IsEquivalentTo(expectedExtensions);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) )";

        var actual = new DITContentRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "name1", "name2" });

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 NAME ( 'name1' 'name2' ) )");
    }

    [Test]
    public async Task ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE )";

        var actual = new DITContentRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Obsolete).IsTrue();

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 OBSOLETE )");
    }

    [Test]
    public async Task ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = await Assert.That(() => new DITContentRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITContentRuleDescription value does not start with '('");
    }

    [Test]
    public async Task ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = await Assert.That(() => new DITContentRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITContentRuleDescription value does not end with ')'");
    }

    [Test]
    public async Task NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = await Assert.That(() => new DITContentRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITContentRuleDescription OID value is invalid");
    }

    [Test]
    public async Task InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure )";

        var ex = await Assert.That(() => new DITContentRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITContentRuleDescription NAME value is invalid");
    }
}
