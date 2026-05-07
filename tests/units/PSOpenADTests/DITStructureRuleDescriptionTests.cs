using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using TUnit.Core;

namespace PSOpenADTests;

public class DITStructureRuleDescriptionTests
{
    [Test]
    public async Task ParseDITStructureRuleDescription()
    {
        const string VALUE = "( 2 DESC 'organization structure rule' FORM 2.5.15.3 )";

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("2");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsEqualTo("organization structure rule");
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Form).IsEqualTo("2.5.15.3");
        await Assert.That(actual.SuperRules).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseNoOptional()
    {
        const string VALUE = "( 0 FORM 2.0 )";

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("0");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Form).IsEqualTo("2.0");
        await Assert.That(actual.SuperRules).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithExtensions()
    {
        const string VALUE = "( 1 FORM 2.1 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1 FORM 2.1 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("1");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.Form).IsEqualTo("2.1");
        await Assert.That(actual.SuperRules).IsEmpty();
        await Assert.That(actual.Extensions).IsEquivalentTo(expectedExtensions);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseWithMultipleNames()
    {
        const string VALUE = "(9  NAME ('name1' 'name2' ) FORM 2.1010.98)";

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("9");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "name1", "name2" });
        await Assert.That(actual.Form).IsEqualTo("2.1010.98");

        await Assert.That(actual.ToString()).IsEqualTo("( 9 NAME ( 'name1' 'name2' ) FORM 2.1010.98 )");
    }

    [Test]
    public async Task ParseWithDescription()
    {
        const string VALUE = "( 9 DESC 'testing 123' FORM 2.1010.98 )";

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("9");
        await Assert.That(actual.Description).IsEqualTo("testing 123");
        await Assert.That(actual.Form).IsEqualTo("2.1010.98");

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithObsolete()
    {
        const string VALUE = "( 272 OBSOLETE FORM 10.0)";

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("272");
        await Assert.That(actual.Obsolete).IsTrue();

        await Assert.That(actual.ToString()).IsEqualTo("( 272 OBSOLETE FORM 10.0 )");
    }

    [Test]
    public async Task ParseWithSingleSupRule()
    {
        const string VALUE = "( 1 FORM 2.3 SUP 12039 )";

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("1");
        await Assert.That(actual.Form).IsEqualTo("2.3");
        await Assert.That(actual.SuperRules).IsEquivalentTo(new[] { "12039" });

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithMultipleSupRules()
    {
        const string VALUE = "( 1 FORM 2.3 SUP ( 12039 351835 ) )";

        var actual = new DITStructureRuleDescription(VALUE);

        await Assert.That(actual.Id).IsEqualTo("1");
        await Assert.That(actual.Form).IsEqualTo("2.3");
        await Assert.That(actual.SuperRules).IsEquivalentTo(new[] { "12039", "351835" });

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ValueDoesNotStartWithParen()
    {
        const string VALUE = "1 FORM 2.3 )";

        var ex = await Assert.That(() => new DITStructureRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITStructureRuleDescription value does not start with '('");
    }

    [Test]
    public async Task ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1 FORM 2.3";

        var ex = await Assert.That(() => new DITStructureRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITStructureRuleDescription value does not end with ')'");
    }

    [Test]
    public async Task NoIDValue()
    {
        const string VALUE = "( FORM 2.3 )";

        var ex = await Assert.That(() => new DITStructureRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITStructureRuleDescription ID value is invalid");
    }

    [Test]
    public async Task InvalidFieldValue()
    {
        const string VALUE = "( 1 FORM 2.3 SUP-1234 )";

        var ex = await Assert.That(() => new DITStructureRuleDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid DITStructureRuleDescription SUP value is invalid");
    }
}
