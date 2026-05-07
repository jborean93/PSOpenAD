using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using TUnit.Core;

namespace PSOpenADTests;

public class SyntaxDescriptionTests
{
    [Test]
    public async Task ParseSyntaxDescription()
    {
        const string VALUE = "( 1.3.6.1.4.1.1466.115.121.1.54 DESC 'LDAP Syntax Description' )";

        var actual = new SyntaxDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.3.6.1.4.1.1466.115.121.1.54");
        await Assert.That(actual.Description).IsEqualTo("LDAP Syntax Description");
        await Assert.That(actual.Extensions.Count).IsEqualTo(0);

        await Assert.That(actual.ToString()).IsEqualTo(VALUE);
    }

    [Test]
    public async Task ParseWithExtensions()
    {
        const string VALUE = "(  1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ('\\27ext 1\\27'   'ext 2' ))";
        const string EXPECTED_STR = "( 1.0 X-ORIGIN 'RFC 1274' X-OTHER-abc ( '\\27ext 1\\27' 'ext 2' ) )";
        Dictionary<string, string[]> expectedExtensions = new()
        {
            { "X-ORIGIN", new[] { "RFC 1274" } },
            { "X-OTHER-abc", new[] { "'ext 1'", "ext 2" } },
        };

        var actual = new SyntaxDescription(VALUE);

        await Assert.That(actual.OID).IsEqualTo("1.0");
        await Assert.That(actual.Description).IsNull();
        await Assert.That(actual.Extensions).IsEquivalentTo(expectedExtensions);

        await Assert.That(actual.ToString()).IsEqualTo(EXPECTED_STR);
    }

    [Test]
    public async Task ValueDoesNotStartWithParen()
    {
        const string VALUE = "1.0 )";

        var ex = await Assert.That(() => new SyntaxDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid SyntaxDescription value does not start with '('");
    }

    [Test]
    public async Task ValueDoesNotEndWithParen()
    {
        const string VALUE = "( 1.0 ";

        var ex = await Assert.That(() => new SyntaxDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid SyntaxDescription value does not end with ')'");
    }

    [Test]
    public async Task InvlaidOIDValue()
    {
        const string VALUE = "( 'abc' )";

        var ex = await Assert.That(() => new SyntaxDescription(VALUE)).Throws<FormatException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid SyntaxDescription OID value is invalid");
    }
}
