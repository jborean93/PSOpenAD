using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using TUnit.Core;

namespace PSOpenADTests;

public class ObjectClassDescriptionTests
{
    [Test]
    public async Task ParseAttributeDescription()
    {
        const string VALUE = "( 2.5.6.2 NAME 'country' SUP top STRUCTURAL MUST c MAY ( searchGuide $ description ) )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.6.2");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "country" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.SuperTypes).IsEquivalentTo(new[] { "top" });
        await Assert.That(actual.Kind).IsEqualTo(ObjectClassKind.Structural);
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "c" });
        await Assert.That(actual.May).IsEquivalentTo(new[] { "searchGuide", "description" });
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseAttributeDescriptionAD()
    {
        const string VALUE = "( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST (cn ) MAY (serialNumber $ l $ o $ ou $ owner $ seeAlso $ msSFU30Name $ msSFU30Aliases $ msSFU30NisDomain $ nisMapName ) )";
        const string EXPECTED_STR = "( 2.5.6.14 NAME 'device' SUP top STRUCTURAL MUST cn MAY ( serialNumber $ l $ o $ ou $ owner $ seeAlso $ msSFU30Name $ msSFU30Aliases $ msSFU30NisDomain $ nisMapName ) )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("2.5.6.14");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "device" });
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.SuperTypes).IsEquivalentTo(new[] { "top" });
        await Assert.That(actual.Kind).IsEqualTo(ObjectClassKind.Structural);
        await Assert.That(actual.Must).IsEquivalentTo(new[] { "cn" });
        await Assert.That(actual.May).IsEquivalentTo(new[] { "serialNumber", "l", "o", "ou", "owner", "seeAlso", "msSFU30Name", "msSFU30Aliases",
            "msSFU30NisDomain", "nisMapName" });
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseNoOptional()
    {
        const string VALUE = "( 1.0 )";
        const string EXPECTED_STR = "( 1.0 STRUCTURAL )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.SuperTypes).IsEmpty();
        await Assert.That(actual.Kind).IsEqualTo(ObjectClassKind.Structural);
        await Assert.That(actual.Must).IsEmpty();
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseWithExtensions()
    {
        const string VALUE = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 STRUCTURAL X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEmpty();
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.SuperTypes).IsEmpty();
        await Assert.That(actual.Kind).IsEqualTo(ObjectClassKind.Structural);
        await Assert.That(actual.Must).IsEmpty();
        await Assert.That(actual.May).IsEmpty();
        await Assert.That(actual.Extensions).IsEquivalentTo(expectedExtensions);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ParseWithMultipleNames()
    {
        const string VALUE = "(1.0  NAME ('name1' 'name2' ) )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Names).IsEquivalentTo(new[] { "name1", "name2" });

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 NAME ( 'name1' 'name2' ) STRUCTURAL )");
    }

    [Test]
    public async Task ParseWithDescription()
    {
        const string VALUE = "( 1.0 DESC   'foo \\27bar\\27' )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Description).IsEqualTo("foo 'bar'");

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 DESC 'foo \\27bar\\27' STRUCTURAL )");
    }

    [Test]
    public async Task ParseWithObsolete()
    {
        const string VALUE = "( 1.0 OBSOLETE )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Obsolete).IsTrue();

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 OBSOLETE STRUCTURAL )");
    }

    [Test]
    public async Task ParseWithOneSuperType()
    {
        const string VALUE = "(1.0  SUP 1.2.3.4 )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.SuperTypes).IsEquivalentTo(new[] { "1.2.3.4" });

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 SUP 1.2.3.4 STRUCTURAL )");
    }

    [Test]
    public async Task ParseWithMultipleSuperType()
    {
        const string VALUE = "(1.0  SUP (name$1.10.3845 $other ) )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.SuperTypes).IsEquivalentTo(new[] { "name", "1.10.3845", "other" });

        await Assert.That(actual.ToString()).IsEqualTo("( 1.0 SUP ( name $ 1.10.3845 $ other ) STRUCTURAL )");
    }

    [Test]
    public async Task ParseAbstractKind()
    {
        const string VALUE = "( 1.0 ABSTRACT )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Kind).IsEqualTo(ObjectClassKind.Abstract);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseAuxiliaryKind()
    {
        const string VALUE = "( 1.0 AUXILIARY )";

        var actual = new ObjectClassDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Kind).IsEqualTo(ObjectClassKind.Auxiliary);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = await Assert.That(() => new ObjectClassDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid ObjectClassDescription value does not start with '('");
    }

    [Test]
    public async Task ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = await Assert.That(() => new ObjectClassDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid ObjectClassDescription value does not end with ')'");
    }

    [Test]
    public async Task NoOIDValue()
    {
        const string VALUE = "( NAME 'test' )";

        var ex = await Assert.That(() => new ObjectClassDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid ObjectClassDescription OID value is invalid");
    }

    [Test]
    public async Task InvalidFieldValue()
    {
        const string VALUE = "( 1.0 NAME failure )";

        var ex = await Assert.That(() => new ObjectClassDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid ObjectClassDescription NAME value is invalid");
    }
}
