using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using TUnit.Core;

namespace PSOpenADTests;

public class NameFormDescriptionTests
{
    [Test]
    public async Task ParseNameFormDescription()
    {
        const string VALUE = "( 2.5.15.3 NAME 'orgNameForm' OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.15.3");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "orgNameForm" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.ObjectClass).IsEqualTo("organization");
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "o" });
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseNoOptional()
    {
        const string VALUE = "( 2.5.15.3 OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.15.3");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.ObjectClass).IsEqualTo("organization");
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "o" });
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithExtensions()
    {
        const string VALUE = "( 2.5.15.3 OC organization MUST o X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 2.5.15.3 OC organization MUST o X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new NameFormDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.15.3");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.ObjectClass).IsEqualTo("organization");
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "o" });
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Extensions).IsEquivalentTo(expectedExtensions);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) OC 10.3 MUST (o$3.0.1) )";

        var actual = new NameFormDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "name1", "name2" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Obsolete).IsFalse();
        await Assert.That(actual.ObjectClass).IsEqualTo("10.3");
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "o", "3.0.1" });
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 NAME ( 'name1' 'name2' ) OC 10.3 MUST ( o $ 3.0.1 ) )");
    }

    [Test]
    public async Task ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Description).IsEqualTo("foo 'bar'");

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 DESC 'foo \\27bar\\27' OC organization MUST o )");
    }

    [Test]
    public async Task ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE OC organization MUST o )";

        var actual = new NameFormDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Obsolete).IsTrue();

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithMay()
    {
        const string VALUE = "( 1.0 OC organization MUST o MAY (abc$ def$134.0 ))";

        var actual = new NameFormDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.May).IsEquivalentTo(new[] { "abc", "def", "134.0" });

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 OC organization MUST o MAY ( abc $ def $ 134.0 ) )");
    }

    [Test]
    public async Task ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = await Assert.That(() => new NameFormDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid NameFormDescription value does not start with '('");
    }

    [Test]
    public async Task NoOCValue()
    {
        const string VALUE = "( 1.0 MUST o )";

        var ex = await Assert.That(() => new NameFormDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid NameFormDescription OC value is missing");
    }

    [Test]
    public async Task NoMustValue()
    {
        const string VALUE = "( 1.0 OC o )";

        var ex = await Assert.That(() => new NameFormDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid NameFormDescription MUST value is missing");
    }

    [Test]
    public async Task ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 OC test MUST abc ";

        var ex = await Assert.That(() => new NameFormDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid NameFormDescription value does not end with ')'");
    }

    [Test]
    public async Task NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = await Assert.That(() => new NameFormDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid NameFormDescription OID value is invalid");
    }

    [Test]
    public async Task InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure )";

        var ex = await Assert.That(() => new NameFormDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid NameFormDescription NAME value is invalid");
    }
}
