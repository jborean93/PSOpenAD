using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using TUnit.Core;

namespace PSOpenADTests;

public class MatchingRuleDescriptionTests
{
    [Test]
    public async Task ParseMatchingRuleDescription()
    {
        const string VALUE = "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";

        var actual = new MatchingRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.13.2");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "caseIgnoreMatch" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Syntax).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.15");
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseNoOptional()
    {
        const string VALUE = "( 2.5.13.2 SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";

        var actual = new MatchingRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.13.2");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Syntax).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.15");
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithExtensions()
    {
        const string VALUE = "( 1.0 SYNTAX 1.2 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 SYNTAX 1.2 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new MatchingRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Syntax).IsEqualTo("1.2");
        await Assert.That(actual.Extensions).IsEquivalentTo(expectedExtensions);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) SYNTAX 1.2 )";

        var actual = new MatchingRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "name1", "name2" });

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 NAME ( 'name1' 'name2' ) SYNTAX 1.2 )");
    }

    [Test]
    public async Task ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' SYNTAX 1.2 )";

        var actual = new MatchingRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Description).IsEqualTo("foo 'bar'");

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 DESC 'foo \\27bar\\27' SYNTAX 1.2 )");
    }

    [Test]
    public async Task ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE SYNTAX 1.2)";

        var actual = new MatchingRuleDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Obsolete).IsTrue();

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 OBSOLETE SYNTAX 1.2 )");
    }

    [Test]
    public async Task ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 SYNTAX 1.2 )";

        var ex = await Assert.That(() => new MatchingRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid MatchingRuleDescription value does not start with '('");
    }

    [Test]
    public async Task ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 SYNTAX 1.2 ";

        var ex = await Assert.That(() => new MatchingRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid MatchingRuleDescription value does not end with ')'");
    }

    [Test]
    public async Task NoSyntaxValue()
    {
        const string VALUE = "( 1.2 )";

        var ex = await Assert.That(() => new MatchingRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid MatchingRuleDescription SYNTAX value is missing");
    }

    [Test]
    public async Task InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure SYNTAX 1.2 )";

        var ex = await Assert.That(() => new MatchingRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid MatchingRuleDescription NAME value is invalid");
    }
}
