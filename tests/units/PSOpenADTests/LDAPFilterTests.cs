using PSOpenAD.LDAP;
using System;
using System.Threading.Tasks;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using TUnit.Core;

namespace PSOpenADTests;

public class LDAPFilterGenericTests
{
    [Test]
    public async Task InvalidLDAPFilterExceptionDefault()
    {
        var ex = new InvalidLDAPFilterException();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("One of the identified items was in an invalid format.");
        await Assert.That(ex.InnerException == null).IsTrue();
        await Assert.That(ex.Filter).IsEqualTo("");
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(0);
    }

    [Test]
    public async Task InvalidLDAPFilterExceptionMessage()
    {
        var ex = new InvalidLDAPFilterException("message");
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("message");
        await Assert.That(ex.InnerException == null).IsTrue();
        await Assert.That(ex.Filter).IsEqualTo("");
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(0);
    }

    [Test]
    public async Task InvalidLDAPFilterExceptionInnerException()
    {
        var ex = new InvalidLDAPFilterException("message", new Exception("inner"));
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("message");
        await Assert.That(ex.InnerException != null).IsTrue();
        await Assert.That(ex.InnerException).IsTypeOf<Exception>();
        await Assert.That(ex.InnerException?.Message).IsEqualTo("inner");
        await Assert.That(ex.Filter).IsEqualTo("");
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(0);
    }

    [Test]
    public async Task InvalidFilterExtraData()
    {
        const string filter = "(objectClass=*)foo=bar";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Extra data found at filter end");
        await Assert.That(ex.StartPosition).IsEqualTo(15);
        await Assert.That(ex.EndPosition).IsEqualTo(22);
    }

    [Test]
    public async Task InvalidFilterUnbalanceClosingParen()
    {
        const string filter = ")";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Unbalanced closing ')' without a starting '('");
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(1);
    }

    [Test]
    public async Task InvalidFilterNestedComplexWithoutConditional()
    {
        const string filter = "((objectClass=*))";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Nested '(' without filter condition");
        await Assert.That(ex.StartPosition).IsEqualTo(1);
        await Assert.That(ex.EndPosition).IsEqualTo(2);
    }

    [Test]
    public async Task InvalidFilterUnbalanceNoClosingSimple()
    {
        const string filter = "(objectClass=*";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Unbalanced starting '(' without a closing ')'");
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(14);
    }

    [Test]
    public async Task InvalidFilterNoFilter()
    {
        const string filter = "()";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("No filter found");
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(2);
    }
}

public class LDAPFilterAndTests
{
    [Test]
    public async Task FilterAndSimple()
    {
        const string filter = "(&(foo=bar)(attr=*))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterAnd>();
        await Assert.That(parsedFilter.ToString()).IsEqualTo(filter);

        FilterAnd actual = (FilterAnd)parsedFilter;

        await Assert.That(actual.Filters.Length).IsEqualTo(2);

        await Assert.That(actual.Filters[0]).IsTypeOf<FilterEquality>();
        FilterEquality filterEntry = (FilterEquality)actual.Filters[0];
        await Assert.That(filterEntry.Attribute).IsEqualTo("foo");
        await Assert.That(Encoding.UTF8.GetString(filterEntry.Value.Span)).IsEqualTo("bar");

        await Assert.That(actual.Filters[1]).IsTypeOf<FilterPresent>();
        FilterPresent filterPresent = (FilterPresent)actual.Filters[1];
        await Assert.That(filterPresent.Attribute).IsEqualTo("attr");
    }

    [Test]
    public async Task FilterAndCompound()
    {
        const string filter = "(&(foo=bar)(&(attr=abc*test*end)(attr:rule:=test)(&(test>=1))))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterAnd>();
        await Assert.That(parsedFilter.ToString()).IsEqualTo(filter);

        FilterAnd actual = (FilterAnd)parsedFilter;

        await Assert.That(actual.Filters.Length).IsEqualTo(2);

        await Assert.That(actual.Filters[0]).IsTypeOf<FilterEquality>();
        FilterEquality filterEquals = (FilterEquality)actual.Filters[0];
        await Assert.That(filterEquals.Attribute).IsEqualTo("foo");
        await Assert.That(Encoding.UTF8.GetString(filterEquals.Value.Span)).IsEqualTo("bar");

        await Assert.That(actual.Filters[1]).IsTypeOf<FilterAnd>();
        FilterAnd filterAnd = (FilterAnd)actual.Filters[1];
        await Assert.That(filterAnd.Filters.Length).IsEqualTo(3);

        await Assert.That(filterAnd.Filters[0]).IsTypeOf<FilterSubstrings>();
        FilterSubstrings filterSubstrings = (FilterSubstrings)filterAnd.Filters[0];
        await Assert.That(filterSubstrings.Attribute).IsEqualTo("attr");
        await Assert.That(filterSubstrings.Initial != null).IsTrue();
        await Assert.That(Encoding.UTF8.GetString((filterSubstrings.Initial ?? Array.Empty<byte>()).Span)).IsEqualTo("abc");
        await Assert.That(filterSubstrings.Any).HasSingleItem();
        await Assert.That(Encoding.UTF8.GetString(filterSubstrings.Any[0].Span)).IsEqualTo("test");
        await Assert.That(filterSubstrings.Final != null).IsTrue();
        await Assert.That(Encoding.UTF8.GetString((filterSubstrings.Final ?? Array.Empty<byte>()).Span)).IsEqualTo("end");

        await Assert.That(filterAnd.Filters[1]).IsTypeOf<FilterExtensibleMatch>();
        FilterExtensibleMatch filterExtensible = (FilterExtensibleMatch)filterAnd.Filters[1];
        await Assert.That(filterExtensible.Attribute).IsEqualTo("attr");
        await Assert.That(filterExtensible.MatchingRule).IsEqualTo("rule");
        await Assert.That(filterExtensible.DNAttributes).IsFalse();
        await Assert.That(Encoding.UTF8.GetString(filterExtensible.Value.Span)).IsEqualTo("test");

        await Assert.That(filterAnd.Filters[2]).IsTypeOf<FilterAnd>();
        filterAnd = (FilterAnd)filterAnd.Filters[2];
        await Assert.That(filterAnd.Filters).HasSingleItem();

        await Assert.That(filterAnd.Filters[0]).IsTypeOf<FilterGreaterOrEqual>();
        FilterGreaterOrEqual filterGreater = (FilterGreaterOrEqual)filterAnd.Filters[0];
        await Assert.That(filterGreater.Attribute).IsEqualTo("test");
        await Assert.That(Encoding.UTF8.GetString(filterGreater.Value.Span)).IsEqualTo("1");
    }

    [Test]
    public async Task FilterAndToBytes()
    {
        const string expected = "oEmjCgQDZm9vBANiYXKgO6QYBARhdHRyMBCAA2FiY4EEdGVzdIIDZW5kqRKBBHJ1bGWCBGF0dHKDBHRlc3SgC6UJBAR0ZXN0BAEx";

        const string filter = "(&(foo=bar)(&(attr=abc*test*end)(attr:rule:=test)(&(test>=1))))";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task InvalidFilterAndNoNewGroup()
    {
        const string filter = "(&(objectClass=*)foo=bar)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Expecting ')' to end complex filter expression");
        await Assert.That(ex.StartPosition).IsEqualTo(17);
        await Assert.That(ex.EndPosition).IsEqualTo(18);
    }

    [Test]
    public async Task InvalidFilterAndNotStarted()
    {
        const string filter = "(&objectClass=*)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Expecting '(' to start after qualifier in complex filter expression");
        await Assert.That(ex.StartPosition).IsEqualTo(2);
        await Assert.That(ex.EndPosition).IsEqualTo(3);
    }

    [Test]
    public async Task InvalidFilterAndNoValue()
    {
        const string filter = "(&)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("No filter value found after conditional");
        await Assert.That(ex.StartPosition).IsEqualTo(1);
        await Assert.That(ex.EndPosition).IsEqualTo(3);
    }
}

public class LDAPFilterOrTests
{
    [Test]
    public async Task FilterOrSimple()
    {
        const string filter = "(|(foo=bar)(attr=*))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterOr>();
        await Assert.That(parsedFilter.ToString()).IsEqualTo(filter);

        FilterOr actual = (FilterOr)parsedFilter;

        await Assert.That(actual.Filters.Length).IsEqualTo(2);

        await Assert.That(actual.Filters[0]).IsTypeOf<FilterEquality>();
        FilterEquality filterEntry = (FilterEquality)actual.Filters[0];
        await Assert.That(filterEntry.Attribute).IsEqualTo("foo");
        await Assert.That(Encoding.UTF8.GetString(filterEntry.Value.Span)).IsEqualTo("bar");

        await Assert.That(actual.Filters[1]).IsTypeOf<FilterPresent>();
        FilterPresent filterPresent = (FilterPresent)actual.Filters[1];
        await Assert.That(filterPresent.Attribute).IsEqualTo("attr");
    }

    [Test]
    public async Task FilterOrCompound()
    {
        const string filter = "(|(foo=bar)(|(attr=*)(attr:dn:rule:=test)(&(test<=1))))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterOr>();
        await Assert.That(parsedFilter.ToString()).IsEqualTo(filter);

        FilterOr actual = (FilterOr)parsedFilter;

        await Assert.That(actual.Filters.Length).IsEqualTo(2);

        await Assert.That(actual.Filters[0]).IsTypeOf<FilterEquality>();
        FilterEquality filterEquals = (FilterEquality)actual.Filters[0];
        await Assert.That(filterEquals.Attribute).IsEqualTo("foo");
        await Assert.That(Encoding.UTF8.GetString(filterEquals.Value.Span)).IsEqualTo("bar");

        await Assert.That(actual.Filters[1]).IsTypeOf<FilterOr>();
        FilterOr filterOr = (FilterOr)actual.Filters[1];
        await Assert.That(filterOr.Filters.Length).IsEqualTo(3);

        await Assert.That(filterOr.Filters[0]).IsTypeOf<FilterPresent>();
        FilterPresent filterPresent = (FilterPresent)filterOr.Filters[0];
        await Assert.That(filterPresent.Attribute).IsEqualTo("attr");

        await Assert.That(filterOr.Filters[1]).IsTypeOf<FilterExtensibleMatch>();
        FilterExtensibleMatch filterExtensible = (FilterExtensibleMatch)filterOr.Filters[1];
        await Assert.That(filterExtensible.Attribute).IsEqualTo("attr");
        await Assert.That(filterExtensible.MatchingRule).IsEqualTo("rule");
        await Assert.That(filterExtensible.DNAttributes).IsTrue();
        await Assert.That(Encoding.UTF8.GetString(filterExtensible.Value.Span)).IsEqualTo("test");

        await Assert.That(filterOr.Filters[2]).IsTypeOf<FilterAnd>();
        FilterAnd filterAnd = (FilterAnd)filterOr.Filters[2];
        await Assert.That(filterAnd.Filters).HasSingleItem();

        await Assert.That(filterAnd.Filters[0]).IsTypeOf<FilterLessOrEqual>();
        FilterLessOrEqual filterLess = (FilterLessOrEqual)filterAnd.Filters[0];
        await Assert.That(filterLess.Attribute).IsEqualTo("test");
        await Assert.That(Encoding.UTF8.GetString(filterLess.Value.Span)).IsEqualTo("1");
    }

    [Test]
    public async Task FilterOrToBytes()
    {
        const string expected = "oTijCgQDZm9vBANiYXKhKocEYXR0cqkVgQRydWxlggRhdHRygwR0ZXN0hAH/oAumCQQEdGVzdAQBMQ==";

        const string filter = "(|(foo=bar)(|(attr=*)(attr:dn:rule:=test)(&(test<=1))))";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task InvalidFilterOrNoNewGroup()
    {
        const string filter = "(|(objectClass=*)foo=bar)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Expecting ')' to end complex filter expression");
        await Assert.That(ex.StartPosition).IsEqualTo(17);
        await Assert.That(ex.EndPosition).IsEqualTo(18);
    }

    [Test]
    public async Task InvalidFilterAndOrStarted()
    {
        const string filter = "(|objectClass=*)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Expecting '(' to start after qualifier in complex filter expression");
        await Assert.That(ex.StartPosition).IsEqualTo(2);
        await Assert.That(ex.EndPosition).IsEqualTo(3);
    }

    [Test]
    public async Task InvalidFilterOrNoValue()
    {
        const string filter = "(|)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("No filter value found after conditional");
        await Assert.That(ex.StartPosition).IsEqualTo(1);
        await Assert.That(ex.EndPosition).IsEqualTo(3);
    }
}

public class LDAPFilterNotTests
{
    [Test]
    public async Task FilterNotSimple()
    {
        const string filter = "(!(foo=bar))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterNot>();
        await Assert.That(parsedFilter.ToString()).IsEqualTo(filter);

        FilterNot actual = (FilterNot)parsedFilter;

        await Assert.That(actual.Filter).IsTypeOf<FilterEquality>();
        await Assert.That(((FilterEquality)actual.Filter).Attribute).IsEqualTo("foo");
        await Assert.That(Encoding.UTF8.GetString(((FilterEquality)actual.Filter).Value.Span)).IsEqualTo("bar");
    }

    [Test]
    public async Task FilterNotCompound()
    {
        const string filter = "(!(!(foo=bar)))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterNot>();
        await Assert.That(parsedFilter.ToString()).IsEqualTo(filter);

        FilterNot actual = (FilterNot)parsedFilter;
        await Assert.That(actual.Filter).IsTypeOf<FilterNot>();

        actual = (FilterNot)actual.Filter;
        await Assert.That(((FilterEquality)actual.Filter).Attribute).IsEqualTo("foo");
        await Assert.That(Encoding.UTF8.GetString(((FilterEquality)actual.Filter).Value.Span)).IsEqualTo("bar");
    }

    [Test]
    public async Task FilterNotToBytes()
    {
        const string expected = "og6iDKMKBANmb28EA2Jhcg==";

        const string filter = "(!(!(foo=bar)))";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task InvalidFilterNotMultiple()
    {
        const string filter = "(!(objectClass=*)(foo=bar))";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Multiple filters found for not '!' expression");
        await Assert.That(ex.StartPosition).IsEqualTo(1);
        await Assert.That(ex.EndPosition).IsEqualTo(26);
    }

    [Test]
    public async Task InvalidFilterNotNotStarted()
    {
        const string filter = "(!objectClass=*)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Expecting '(' to start after qualifier in complex filter expression");
        await Assert.That(ex.StartPosition).IsEqualTo(2);
        await Assert.That(ex.EndPosition).IsEqualTo(3);
    }

    [Test]
    public async Task InvalidFilterNotNoValue()
    {
        const string filter = "(!)";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("No filter value found after conditional");
        await Assert.That(ex.StartPosition).IsEqualTo(1);
        await Assert.That(ex.EndPosition).IsEqualTo(3);
    }
}

public class LDAPFilterEqualityTests
{
    [Test]
    [Arguments("objectClass=user", "objectClass", "user")]
    [Arguments("(objectClass=user)", "objectClass", "user")]
    [Arguments("objectClass;test=abc\\20def", "objectClass;test", "abc def")]
    public async Task EqualityFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterEquality>();
        await Assert.That(((FilterEquality)parsedFilter).Attribute).IsEqualTo(attribute);
        await Assert.That(Encoding.UTF8.GetString(((FilterEquality)parsedFilter).Value.Span)).IsEqualTo(value);
    }

    [Test]
    public async Task FilterEqualityToBytes()
    {
        const string expected = "oyUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task EqualityToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo=happy\\20☺ café\\2a");

        await Assert.That(filter.ToString()).IsEqualTo("(foo=happy \\e2\\98\\ba caf\\c3\\a9\\2a)");
    }
}

public class LDAPFilterSubstringsTests
{
    [Test]
    [Arguments("attr=test*value", "attr", "test", new string[0], "value", false)]
    [Arguments("attr=test*value", "attr", "test", new string[0], "value", true)]
    [Arguments("attr=test*", "attr", "test", new string[0], null, false)]
    [Arguments("attr=test*", "attr", "test", new string[0], null, true)]
    [Arguments("attr=*test", "attr", null, new string[0], "test", false)]
    [Arguments("attr=*test", "attr", null, new string[0], "test", true)]
    [Arguments("attr=initial*any*final", "attr", "initial", new[] { "any" }, "final", false)]
    [Arguments("attr=initial*any*final", "attr", "initial", new[] { "any" }, "final", true)]
    [Arguments("attr=*any1*any2*", "attr", null, new[] { "any1", "any2" }, null, false)]
    [Arguments("attr=*any1*any2*", "attr", null, new[] { "any1", "any2" }, null, true)]
    [Arguments("attr=initial*any1*any2*", "attr", "initial", new[] { "any1", "any2" }, null, false)]
    [Arguments("attr=initial*any1*any2*", "attr", "initial", new[] { "any1", "any2" }, null, true)]
    [Arguments("attr=*any1*any2*final", "attr", null, new[] { "any1", "any2" }, "final", false)]
    [Arguments("attr=*any1*any2*final", "attr", null, new[] { "any1", "any2" }, "final", true)]
    [Arguments("attr=initial*any1*any2*final", "attr", "initial", new[] { "any1", "any2" }, "final", false)]
    [Arguments("attr=initial*any1*any2*final", "attr", "initial", new[] { "any1", "any2" }, "final", true)]
    public async Task SubstringsFilter(string filter, string attribute, string? initial, string[] any, string? final,
        bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterSubstrings>();

        FilterSubstrings filterSubstrings = (FilterSubstrings)parsedFilter;
        string? actualInitial = null;
        if (filterSubstrings.Initial != null)
            actualInitial = Encoding.UTF8.GetString(filterSubstrings.Initial?.ToArray() ?? Array.Empty<byte>());

        string[] actualAny = filterSubstrings.Any.Select(v => Encoding.UTF8.GetString(v.Span)).ToArray();

        string? actualFinal = null;
        if (filterSubstrings.Final != null)
            actualFinal = Encoding.UTF8.GetString(filterSubstrings.Final?.ToArray() ?? Array.Empty<byte>());

        await Assert.That(filterSubstrings.Attribute).IsEqualTo(attribute);
        await Assert.That(actualInitial).IsEqualTo(initial);
        await Assert.That(actualAny).IsEquivalentTo(any);
        await Assert.That(actualFinal).IsEqualTo(final);
    }

    [Test]
    [Arguments("objectClass;test=*abc\\20*def ☺ *café*",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCBBWNhZsOp")]
    [Arguments("objectClass;test=abc\\20*def ☺ *café*",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4AEYWJjIIEIZGVmIOKYuiCBBWNhZsOp")]
    [Arguments("objectClass;test=*abc\\20*def ☺ *café",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCCBWNhZsOp")]
    [Arguments("objectClass;test=abc\\20*def ☺ *café",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4AEYWJjIIEIZGVmIOKYuiCCBWNhZsOp")]
    public async Task FilterSubstringsToBytes(string filter, string expected)
    {
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("attr=**", 6, 7, false)]
    [Arguments("attr=**", 7, 8, true)]
    [Arguments("attr=test**remaining", 10, 11, false)]
    [Arguments("attr=test**remaining", 11, 12, true)]
    public async Task InvalidSubstringsTwoAsterisks(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Cannot have 2 consecutive '*' in substring filter");
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }

    [Test]
    [Arguments("foo=*happy\\20☺*café\\2a*", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [Arguments("(foo=*happy\\20☺*café\\2a*)", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [Arguments("foo=happy\\20☺*café\\2a*", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [Arguments("(foo=happy\\20☺*café\\2a*)", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [Arguments("foo=*happy\\20☺*café\\2a", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    [Arguments("(foo=*happy\\20☺*café\\2a)", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    [Arguments("foo=happy\\20☺*café\\2a", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    [Arguments("(foo=happy\\20☺*café\\2a)", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    public async Task SubstringsToString(string filter, string expected)
    {
        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        await Assert.That(actual.ToString()).IsEqualTo(expected);
    }
}

public class LDAPFilterGreaterOrEqualTests
{
    [Test]
    [Arguments("objectClass>=user", "objectClass", "user")]
    [Arguments("(objectClass>=user)", "objectClass", "user")]
    [Arguments("objectClass;test>=\\20abcdef", "objectClass;test", " abcdef")]
    public async Task GreaterOrEqualFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterGreaterOrEqual>();
        await Assert.That(((FilterGreaterOrEqual)parsedFilter).Attribute).IsEqualTo(attribute);
        await Assert.That(Encoding.UTF8.GetString(((FilterGreaterOrEqual)parsedFilter).Value.Span)).IsEqualTo(value);
    }

    [Test]
    public async Task FilterGreaterOrEqualToBytes()
    {
        const string expected = "pSUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test>=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task GreaterOrEqualToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo>=happy\\20☺ café\\2a");

        await Assert.That(filter.ToString()).IsEqualTo("(foo>=happy \\e2\\98\\ba caf\\c3\\a9\\2a)");
    }
}

public class LDAPFilterLessOrEqualTests
{
    [Test]
    [Arguments("objectClass<=user", "objectClass", "user")]
    [Arguments("(objectClass<=user)", "objectClass", "user")]
    [Arguments("objectClass;test<=abcdef\\20", "objectClass;test", "abcdef ")]
    public async Task LessOrEqualFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterLessOrEqual>();
        await Assert.That(((FilterLessOrEqual)parsedFilter).Attribute).IsEqualTo(attribute);
        await Assert.That(Encoding.UTF8.GetString(((FilterLessOrEqual)parsedFilter).Value.Span)).IsEqualTo(value);
    }

    [Test]
    public async Task FilterLessOrEqualToBytes()
    {
        const string expected = "piUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test<=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task LessOrEqualToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo<=happy\\20☺ café\\2a");

        await Assert.That(filter.ToString()).IsEqualTo("(foo<=happy \\e2\\98\\ba caf\\c3\\a9\\2a)");
    }
}

public class LDAPFilterPresentTests
{
    [Test]
    [Arguments("objectClass", false)]
    [Arguments("objectClass", true)]
    [Arguments("1.2.3.4.12912", false)]
    [Arguments("1.2.3.4.12912", true)]
    public async Task PresentFilter(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        await Assert.That(actual).IsTypeOf<FilterPresent>();
        await Assert.That(((FilterPresent)actual).Attribute).IsEqualTo(attribute);
    }

    [Test]
    public async Task FilterPresentToBytes()
    {
        const string expected = "hxIxLjIuMy4zNDEuMC4xO3Rlc3Q=";

        const string filter = "1.2.3.341.0.1;test=*";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task PresentToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo=*");

        await Assert.That(filter.ToString()).IsEqualTo("(foo=*)");
    }
}

public class LDAPFilterApproxMatchTests
{
    [Test]
    [Arguments("objectClass~=user", "objectClass", "user")]
    [Arguments("(objectClass~=user)", "objectClass", "user")]
    [Arguments("objectClass;test~=abc\\20\\2adef", "objectClass;test", "abc *def")]
    public async Task ApproxMatchFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterApproxMatch>();
        await Assert.That(((FilterApproxMatch)parsedFilter).Attribute).IsEqualTo(attribute);
        await Assert.That(Encoding.UTF8.GetString(((FilterApproxMatch)parsedFilter).Value.Span)).IsEqualTo(value);
    }

    [Test]
    public async Task FilterApproxMatchToBytes()
    {
        const string expected = "qCUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test~=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    public async Task ApproxMatchToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo~=happy\\20☺ café\\2a");

        await Assert.That(filter.ToString()).IsEqualTo("(foo~=happy \\e2\\98\\ba caf\\c3\\a9\\2a)");
    }
}

public class LDAPFilterExtensibleMatchTests
{
    [Test]
    [Arguments("attr:=value", null, "attr", "value", false, false)]
    [Arguments("attr:=value", null, "attr", "value", false, true)]
    [Arguments("0:=value", null, "0", "value", false, false)]
    [Arguments("0:=value", null, "0", "value", false, true)]
    [Arguments("1.2:=value", null, "1.2", "value", false, false)]
    [Arguments("1.2:=value", null, "1.2", "value", false, true)]
    [Arguments("4.0.58;option:=value", null, "4.0.58;option", "value", false, false)]
    [Arguments("4.0.58;option:=value", null, "4.0.58;option", "value", false, true)]
    [Arguments("attr:dn:=value", null, "attr", "value", true, false)]
    [Arguments("attr:dn:=value", null, "attr", "value", true, true)]
    [Arguments("8.54.35;option:dn:=value", null, "8.54.35;option", "value", true, false)]
    [Arguments("8.54.35;option:dn:=value", null, "8.54.35;option", "value", true, true)]
    [Arguments("attr:rule:=value", "rule", "attr", "value", false, false)]
    [Arguments("attr:rule:=value", "rule", "attr", "value", false, true)]
    [Arguments("attr:dn:rule:=value", "rule", "attr", "value", true, false)]
    [Arguments("attr:dn:rule:=value", "rule", "attr", "value", true, true)]
    [Arguments("attr:dn:rule;option1:=value", "rule;option1", "attr", "value", true, false)]
    [Arguments("attr:dn:rule;option1:=value", "rule;option1", "attr", "value", true, true)]
    [Arguments("attr;opt:dn:rule;option1:=value", "rule;option1", "attr;opt", "value", true, false)]
    [Arguments("attr;opt:dn:rule;option1:=value", "rule;option1", "attr;opt", "value", true, true)]
    [Arguments(":rule:=value", "rule", null, "value", false, false)]
    [Arguments(":rule:=value", "rule", null, "value", false, true)]
    [Arguments(":0:=value", "0", null, "value", false, false)]
    [Arguments(":0:=value", "0", null, "value", false, true)]
    [Arguments(":0.1:=value", "0.1", null, "value", false, false)]
    [Arguments(":0.1:=value", "0.1", null, "value", false, true)]
    [Arguments(":9.0:=value", "9.0", null, "value", false, false)]
    [Arguments(":9.0:=value", "9.0", null, "value", false, true)]
    [Arguments(":3.84196.0.156:=value", "3.84196.0.156", null, "value", false, false)]
    [Arguments(":3.84196.0.156:=value", "3.84196.0.156", null, "value", false, true)]
    [Arguments(":dn:rule:=value", "rule", null, "value", true, false)]
    [Arguments(":dn:rule:=value", "rule", null, "value", true, true)]
    [Arguments(":dn:6.54.0.58:=value", "6.54.0.58", null, "value", true, false)]
    [Arguments(":dn:6.54.0.58:=value", "6.54.0.58", null, "value", true, true)]
    [Arguments(":rule;option1:=value", "rule;option1", null, "value", false, false)]
    [Arguments(":rule;option1:=value", "rule;option1", null, "value", false, true)]
    [Arguments(":rule;option1;option2:=value", "rule;option1;option2", null, "value", false, false)]
    [Arguments(":rule;option1;option2:=value", "rule;option1;option2", null, "value", false, true)]
    [Arguments(":1.2.548.6;option1;option2:=value", "1.2.548.6;option1;option2", null, "value", false, false)]
    [Arguments(":1.2.548.6;option1;option2:=value", "1.2.548.6;option1;option2", null, "value", false, true)]
    public async Task ExtensibleMatchFilter(string filter, string? matchingRule, string? attribute, string value,
        bool dnAttributes, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        await Assert.That(parsedFilter).IsTypeOf<FilterExtensibleMatch>();

        FilterExtensibleMatch filterExtensible = (FilterExtensibleMatch)parsedFilter;
        await Assert.That(filterExtensible.MatchingRule).IsEqualTo(matchingRule);
        await Assert.That(filterExtensible.Attribute).IsEqualTo(attribute);
        await Assert.That(Encoding.UTF8.GetString(filterExtensible.Value.Span)).IsEqualTo(value);
        await Assert.That(filterExtensible.DNAttributes).IsEqualTo(dnAttributes);
    }

    [Test]
    [Arguments(":=value", 0, 1, false)]
    [Arguments(":=value", 1, 2, true)]
    public async Task InvalidExtensibleNoValue(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Extensible filter must define an attribute and/or rule before ':='");
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }

    [Test]
    [Arguments("1attribute:=value", 0, 10, false)]
    [Arguments("1attribute:=value", 1, 11, true)]
    [Arguments("attr_value:=value", 0, 10, false)]
    [Arguments("attr_value:=value", 1, 11, true)]
    [Arguments("4.7.06.1:=value", 0, 8, false)]
    [Arguments("4.7.06.1:=value", 1, 9, true)]
    [Arguments("attr;option;:=value", 0, 12, false)]
    [Arguments("attr;option;:=value", 1, 13, true)]
    public async Task InvalidExtensibleInvalidAttribute(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid extensible filter attribute value");
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }

    [Test]
    [Arguments("attr:1rule:=value", 5, 10, false)]
    [Arguments("attr:1rule:=value", 6, 11, true)]
    [Arguments("attr:dn:1rule:=value", 8, 13, false)]
    [Arguments("attr:dn:1rule:=value", 9, 14, true)]
    [Arguments("attr:rule_value:=value", 5, 15, false)]
    [Arguments("attr:rule_value:=value", 6, 16, true)]
    [Arguments("attr:4.7.06.1:=value", 5, 13, false)]
    [Arguments("attr:4.7.06.1:=value", 6, 14, true)]
    [Arguments("attr:rule;option;:=value", 5, 17, false)]
    [Arguments("attr:rule;option;:=value", 6, 18, true)]
    public async Task InvalidExtensibleInvalidRule(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid extensible filter rule value");
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }

    [Test]
    [Arguments(":dn:=value", 0, 4, false)]
    [Arguments(":dn:=value", 1, 5, true)]
    public async Task InvalidExtensibleNoAttributeOrRule(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Extensible filter must define the attribute, rule, or both");
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }

    [Test]
    [Arguments("attr:rule:extra:=value", 10, 16, false)]
    [Arguments("attr:rule:extra:=value", 11, 17, true)]
    [Arguments("attr:dn:rule:extra:=value", 13, 19, false)]
    [Arguments("attr:dn:rule:extra:=value", 14, 20, true)]
    [Arguments(":rule:extra:=value", 6, 12, false)]
    [Arguments(":rule:extra:=value", 7, 13, true)]
    [Arguments(":dn:rule:extra:=value", 9, 15, false)]
    [Arguments(":dn:rule:extra:=value", 10, 16, true)]
    public async Task InvalidExtensibleExtraDataBeforeEquals(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Extra data found in extensible filter key");
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }

    [Test]
    [Arguments("foo:=happy\\20☺ café\\2a", "(foo:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [Arguments("(foo:=happy\\20☺ café\\2a)", "(foo:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [Arguments("foo:dn:=happy\\20☺ café\\2a", "(foo:dn:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [Arguments("(foo:dn:=happy\\20☺ café\\2a)", "(foo:dn:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [Arguments("foo:rule:=happy\\20☺ café\\2a", "(foo:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [Arguments("(foo:rule:=happy\\20☺ café\\2a)", "(foo:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [Arguments("foo:dn:rule:=happy\\20☺ café\\2a", "(foo:dn:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [Arguments("(foo:dn:rule:=happy\\20☺ café\\2a)", "(foo:dn:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    public async Task ExtensibleToString(string filter, string expected)
    {
        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        await Assert.That(actual.ToString()).IsEqualTo(expected);
    }
}

public class LDAPFilterAttributeTests
{
    [Test]
    [Arguments("objectClass", false)]
    [Arguments("objectClass", true)]
    [Arguments("sAMAccountName", false)]
    [Arguments("sAMAccountName", true)]
    [Arguments("Test-attr", false)]
    [Arguments("Test-attr", true)]
    [Arguments("test-", false)]
    [Arguments("test-", true)]
    [Arguments("test0", false)]
    [Arguments("test1", true)]
    public async Task AttributeAsString(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        await Assert.That(actual).IsTypeOf<FilterPresent>();
        await Assert.That(((FilterPresent)actual).Attribute).IsEqualTo(attribute);
    }

    [Test]
    [Arguments("0", false)]
    [Arguments("0", true)]
    [Arguments("0.0", false)]
    [Arguments("0.0", true)]
    [Arguments("1.0.1", false)]
    [Arguments("1.0.1", true)]
    [Arguments("9.54", false)]
    [Arguments("9.54", true)]
    [Arguments("3.2.454.23436.1", false)]
    [Arguments("3.2.454.23436.1", true)]
    [Arguments("2.123434.1219214.4394", false)]
    [Arguments("2.123434.1219214.4394", true)]
    public async Task AttributeAsOID(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        await Assert.That(actual).IsTypeOf<FilterPresent>();
        await Assert.That(((FilterPresent)actual).Attribute).IsEqualTo(attribute);
    }

    [Test]
    [Arguments("objectClass;option1", false)]
    [Arguments("objectClass;option1", true)]
    [Arguments("objectClass;option1;option-2", false)]
    [Arguments("objectClass;option1;option-2", true)]
    [Arguments("objectClass;1option", false)]
    [Arguments("objectClass;1option", true)]
    [Arguments("objectClass;-option", false)]
    [Arguments("objectClass;-option", true)]
    [Arguments("1.2.334.1293;option1", false)]
    [Arguments("1.2.334.1293;option1", true)]
    [Arguments("1.2.334.1293;option1;option-2", false)]
    [Arguments("1.2.334.1293;option1;option-2", true)]
    [Arguments("1.2.334.1293;1option", false)]
    [Arguments("1.2.334.1293;1option", true)]
    [Arguments("1.2.334.1293;-option", false)]
    [Arguments("1.2.334.1293;-option", true)]
    public async Task AttributeWithOption(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        await Assert.That(actual).IsTypeOf<FilterPresent>();
        await Assert.That(((FilterPresent)actual).Attribute).IsEqualTo(attribute);
    }

    [Test]
    [Arguments("1attribute=*", 0, 10)] // Must start with a letter
    [Arguments("(1attribute=*)", 1, 11)] // Same as above but wrapped in ()
    [Arguments("(attribute_test=*)", 1, 15)] // Can only contain letters, numbers and -
    [Arguments("1.02.2320=*", 0, 9)] // OID segment must not start with 0 unless it's 0 itself
    [Arguments("attribute;option;=*", 0, 17)] // Option must not end with ;
    public async Task InvalidAttribute(string filter, int expectedStart, int expectedEnd)
    {
        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Invalid filter attribute value");
        await Assert.That(ex.Filter).IsEqualTo(filter);
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }

    [Test]
    public async Task InvalidSimpleFilterFormat()
    {
        const string filter = "=foo";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Simple filter value must not start with '='");
        await Assert.That(ex.Filter).IsEqualTo(filter);
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(1);
    }

    [Test]
    public async Task InvalidSimpleFilterNoEquals()
    {
        const string filter = "foo";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Simple filter missing '=' character");
        await Assert.That(ex.Filter).IsEqualTo(filter);
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(3);
    }

    [Test]
    public async Task InvalidSimpleFilterNoValue()
    {
        const string filter = "foo=";

        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();
        await Assert.That(ex.Message).IsEqualTo("Simple filter value is not present after '='");
        await Assert.That(ex.Filter).IsEqualTo(filter);
        await Assert.That(ex.StartPosition).IsEqualTo(0);
        await Assert.That(ex.EndPosition).IsEqualTo(4);
    }
}

public class LDAPFilterValueTests
{
    [Test]
    [Arguments("simple_123", "simple_123")]
    [Arguments("café", "café")]
    [Arguments("test with space", "test with space")]
    [Arguments("null \\00", "null \0")]
    [Arguments("open paren \\28", "open paren (")]
    [Arguments("close paren \\29", "close paren )")]
    [Arguments("asterisk \\2a", "asterisk *")]
    [Arguments("backslash \\5C", "backslash \\")]
    [Arguments("any escaped \\20", "any escaped  ")]
    [Arguments("happy face \\e2\\98\\BA", "happy face ☺")]
    [Arguments("abc\\ax", "abc\\ax")]
    [Arguments("\\z3 testing", "\\z3 testing")]
    [Arguments("test\\a", "test\\a")]
    [Arguments("testing \\", "testing \\")]
    public async Task ParseSimpleValue(string value, string expected)
    {
        FilterEquality filter = (FilterEquality)LDAPFilter.ParseFilter($"foo={value}");

        string actual = Encoding.UTF8.GetString(filter.Value.Span);

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("objectClass;test:=abc\\20 def ☺ café",
        "qSaCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqQ==")]
    [Arguments("objectClass;test:dn:=abc\\20 def ☺ café",
        "qSmCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqYQB/w==")]
    [Arguments("objectClass;test:rule:=abc\\20 def ☺ café",
        "qSyBBHJ1bGWCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqQ==")]
    [Arguments("objectClass;test:dn:rule:=abc\\20 def ☺ café",
        "qS+BBHJ1bGWCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqYQB/w==")]
    [Arguments(":rule:=abc\\20 def ☺ café",
        "qRqBBHJ1bGWDEmFiYyAgZGVmIOKYuiBjYWbDqQ==")]
    [Arguments(":dn:rule:=abc\\20 def ☺ café",
        "qR2BBHJ1bGWDEmFiYyAgZGVmIOKYuiBjYWbDqYQB/w==")]
    public async Task FilterSubstringsToBytes(string filter, string expected)
    {
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        await Assert.That(actual).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("foo=abc\0", 7, 8)]
    [Arguments("foo=ab(def", 6, 7)]
    public async Task UnescapedCharacter(string filter, int expectedStart, int expectedEnd)
    {
        var ex = await Assert.That(() => LDAPFilter.ParseFilter(filter)).Throws<InvalidLDAPFilterException>();
        await Assert.That(ex).IsNotNull();

        await Assert.That(ex.Message).StartsWith("LDAP filter value contained unescaped char");
        await Assert.That(ex.Filter).IsEqualTo(filter);
        await Assert.That(ex.StartPosition).IsEqualTo(expectedStart);
        await Assert.That(ex.EndPosition).IsEqualTo(expectedEnd);
    }
}
