using PSOpenAD.LDAP;
using System;
using System.Formats.Asn1;
using System.Linq;
using System.Text;
using Xunit;

namespace PSOpenADTests;

public class LDAPFilterGenericTests
{
    [Fact]
    public void InvalidLDAPFilterExceptionDefault()
    {
        var ex = new InvalidLDAPFilterException();

        Assert.Equal("One of the identified items was in an invalid format.", ex.Message);
        Assert.True(ex.InnerException == null);
        Assert.Equal("", ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(0, ex.EndPosition);
    }

    [Fact]
    public void InvalidLDAPFilterExceptionMessage()
    {
        var ex = new InvalidLDAPFilterException("message");

        Assert.Equal("message", ex.Message);
        Assert.True(ex.InnerException == null);
        Assert.Equal("", ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(0, ex.EndPosition);
    }

    [Fact]
    public void InvalidLDAPFilterExceptionInnerException()
    {
        var ex = new InvalidLDAPFilterException("message", new Exception("inner"));

        Assert.Equal("message", ex.Message);
        Assert.True(ex.InnerException != null);
        Assert.IsType<Exception>(ex.InnerException);
        Assert.Equal("inner", ex.InnerException?.Message);
        Assert.Equal("", ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(0, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterExtraData()
    {
        const string filter = "(objectClass=*)foo=bar";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Extra data found at filter end", ex.Message);
        Assert.Equal(15, ex.StartPosition);
        Assert.Equal(22, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterUnbalanceClosingParen()
    {
        const string filter = ")";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Unbalanced closing ')' without a starting '('", ex.Message);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(1, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterNestedComplexWithoutConditional()
    {
        const string filter = "((objectClass=*))";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Nested '(' without filter condition", ex.Message);
        Assert.Equal(1, ex.StartPosition);
        Assert.Equal(2, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterUnbalanceNoClosingSimple()
    {
        const string filter = "(objectClass=*";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Unbalanced starting '(' without a closing ')'", ex.Message);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(14, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterNoFilter()
    {
        const string filter = "()";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("No filter found", ex.Message);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(2, ex.EndPosition);
    }
}

public class LDAPFilterAndTests
{
    [Fact]
    public void FilterAndSimple()
    {
        const string filter = "(&(foo=bar)(attr=*))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterAnd>(parsedFilter);
        Assert.Equal(filter, parsedFilter.ToString());

        FilterAnd actual = (FilterAnd)parsedFilter;

        Assert.Equal(2, actual.Filters.Length);

        Assert.IsType<FilterEquality>(actual.Filters[0]);
        FilterEquality filterEntry = (FilterEquality)actual.Filters[0];
        Assert.Equal("foo", filterEntry.Attribute);
        Assert.Equal("bar", Encoding.UTF8.GetString(filterEntry.Value.Span));

        Assert.IsType<FilterPresent>(actual.Filters[1]);
        FilterPresent filterPresent = (FilterPresent)actual.Filters[1];
        Assert.Equal("attr", filterPresent.Attribute);
    }

    [Fact]
    public void FilterAndCompound()
    {
        const string filter = "(&(foo=bar)(&(attr=abc*test*end)(attr:rule:=test)(&(test>=1))))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterAnd>(parsedFilter);
        Assert.Equal(filter, parsedFilter.ToString());

        FilterAnd actual = (FilterAnd)parsedFilter;

        Assert.Equal(2, actual.Filters.Length);

        Assert.IsType<FilterEquality>(actual.Filters[0]);
        FilterEquality filterEquals = (FilterEquality)actual.Filters[0];
        Assert.Equal("foo", filterEquals.Attribute);
        Assert.Equal("bar", Encoding.UTF8.GetString(filterEquals.Value.Span));

        Assert.IsType<FilterAnd>(actual.Filters[1]);
        FilterAnd filterAnd = (FilterAnd)actual.Filters[1];
        Assert.Equal(3, filterAnd.Filters.Length);

        Assert.IsType<FilterSubstrings>(filterAnd.Filters[0]);
        FilterSubstrings filterSubstrings = (FilterSubstrings)filterAnd.Filters[0];
        Assert.Equal("attr", filterSubstrings.Attribute);
        Assert.True(filterSubstrings.Initial != null);
        Assert.Equal("abc", Encoding.UTF8.GetString((filterSubstrings.Initial ?? Array.Empty<byte>()).Span));
        Assert.Single(filterSubstrings.Any);
        Assert.Equal("test", Encoding.UTF8.GetString(filterSubstrings.Any[0].Span));
        Assert.True(filterSubstrings.Final != null);
        Assert.Equal("end", Encoding.UTF8.GetString((filterSubstrings.Final ?? Array.Empty<byte>()).Span));

        Assert.IsType<FilterExtensibleMatch>(filterAnd.Filters[1]);
        FilterExtensibleMatch filterExtensible = (FilterExtensibleMatch)filterAnd.Filters[1];
        Assert.Equal("attr", filterExtensible.Attribute);
        Assert.Equal("rule", filterExtensible.MatchingRule);
        Assert.False(filterExtensible.DNAttributes);
        Assert.Equal("test", Encoding.UTF8.GetString(filterExtensible.Value.Span));

        Assert.IsType<FilterAnd>(filterAnd.Filters[2]);
        filterAnd = (FilterAnd)filterAnd.Filters[2];
        Assert.Single(filterAnd.Filters);

        Assert.IsType<FilterGreaterOrEqual>(filterAnd.Filters[0]);
        FilterGreaterOrEqual filterGreater = (FilterGreaterOrEqual)filterAnd.Filters[0];
        Assert.Equal("test", filterGreater.Attribute);
        Assert.Equal("1", Encoding.UTF8.GetString(filterGreater.Value.Span));
    }

    [Fact]
    public void FilterAndToBytes()
    {
        const string expected = "oEmjCgQDZm9vBANiYXKgO6QYBARhdHRyMBCAA2FiY4EEdGVzdIIDZW5kqRKBBHJ1bGWCBGF0dHKDBHRlc3SgC6UJBAR0ZXN0BAEx";

        const string filter = "(&(foo=bar)(&(attr=abc*test*end)(attr:rule:=test)(&(test>=1))))";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void InvalidFilterAndNoNewGroup()
    {
        const string filter = "(&(objectClass=*)foo=bar)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Expecting ')' to end complex filter expression", ex.Message);
        Assert.Equal(17, ex.StartPosition);
        Assert.Equal(18, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterAndNotStarted()
    {
        const string filter = "(&objectClass=*)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Expecting '(' to start after qualifier in complex filter expression", ex.Message);
        Assert.Equal(2, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterAndNoValue()
    {
        const string filter = "(&)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("No filter value found after conditional", ex.Message);
        Assert.Equal(1, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }
}

public class LDAPFilterOrTests
{
    [Fact]
    public void FilterOrSimple()
    {
        const string filter = "(|(foo=bar)(attr=*))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterOr>(parsedFilter);
        Assert.Equal(filter, parsedFilter.ToString());

        FilterOr actual = (FilterOr)parsedFilter;

        Assert.Equal(2, actual.Filters.Length);

        Assert.IsType<FilterEquality>(actual.Filters[0]);
        FilterEquality filterEntry = (FilterEquality)actual.Filters[0];
        Assert.Equal("foo", filterEntry.Attribute);
        Assert.Equal("bar", Encoding.UTF8.GetString(filterEntry.Value.Span));

        Assert.IsType<FilterPresent>(actual.Filters[1]);
        FilterPresent filterPresent = (FilterPresent)actual.Filters[1];
        Assert.Equal("attr", filterPresent.Attribute);
    }

    [Fact]
    public void FilterOrCompound()
    {
        const string filter = "(|(foo=bar)(|(attr=*)(attr:dn:rule:=test)(&(test<=1))))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterOr>(parsedFilter);
        Assert.Equal(filter, parsedFilter.ToString());

        FilterOr actual = (FilterOr)parsedFilter;

        Assert.Equal(2, actual.Filters.Length);

        Assert.IsType<FilterEquality>(actual.Filters[0]);
        FilterEquality filterEquals = (FilterEquality)actual.Filters[0];
        Assert.Equal("foo", filterEquals.Attribute);
        Assert.Equal("bar", Encoding.UTF8.GetString(filterEquals.Value.Span));

        Assert.IsType<FilterOr>(actual.Filters[1]);
        FilterOr filterOr = (FilterOr)actual.Filters[1];
        Assert.Equal(3, filterOr.Filters.Length);

        Assert.IsType<FilterPresent>(filterOr.Filters[0]);
        FilterPresent filterPresent = (FilterPresent)filterOr.Filters[0];
        Assert.Equal("attr", filterPresent.Attribute);

        Assert.IsType<FilterExtensibleMatch>(filterOr.Filters[1]);
        FilterExtensibleMatch filterExtensible = (FilterExtensibleMatch)filterOr.Filters[1];
        Assert.Equal("attr", filterExtensible.Attribute);
        Assert.Equal("rule", filterExtensible.MatchingRule);
        Assert.True(filterExtensible.DNAttributes);
        Assert.Equal("test", Encoding.UTF8.GetString(filterExtensible.Value.Span));

        Assert.IsType<FilterAnd>(filterOr.Filters[2]);
        FilterAnd filterAnd = (FilterAnd)filterOr.Filters[2];
        Assert.Single(filterAnd.Filters);

        Assert.IsType<FilterLessOrEqual>(filterAnd.Filters[0]);
        FilterLessOrEqual filterLess = (FilterLessOrEqual)filterAnd.Filters[0];
        Assert.Equal("test", filterLess.Attribute);
        Assert.Equal("1", Encoding.UTF8.GetString(filterLess.Value.Span));
    }

    [Fact]
    public void FilterOrToBytes()
    {
        const string expected = "oTijCgQDZm9vBANiYXKhKocEYXR0cqkVgQRydWxlggRhdHRygwR0ZXN0hAH/oAumCQQEdGVzdAQBMQ==";

        const string filter = "(|(foo=bar)(|(attr=*)(attr:dn:rule:=test)(&(test<=1))))";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void InvalidFilterOrNoNewGroup()
    {
        const string filter = "(|(objectClass=*)foo=bar)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Expecting ')' to end complex filter expression", ex.Message);
        Assert.Equal(17, ex.StartPosition);
        Assert.Equal(18, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterAndOrStarted()
    {
        const string filter = "(|objectClass=*)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Expecting '(' to start after qualifier in complex filter expression", ex.Message);
        Assert.Equal(2, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterOrNoValue()
    {
        const string filter = "(|)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("No filter value found after conditional", ex.Message);
        Assert.Equal(1, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }
}

public class LDAPFilterNotTests
{
    [Fact]
    public void FilterNotSimple()
    {
        const string filter = "(!(foo=bar))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterNot>(parsedFilter);
        Assert.Equal(filter, parsedFilter.ToString());

        FilterNot actual = (FilterNot)parsedFilter;

        Assert.IsType<FilterEquality>(actual.Filter);
        Assert.Equal("foo", ((FilterEquality)actual.Filter).Attribute);
        Assert.Equal("bar", Encoding.UTF8.GetString(((FilterEquality)actual.Filter).Value.Span));
    }

    [Fact]
    public void FilterNotCompound()
    {
        const string filter = "(!(!(foo=bar)))";

        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterNot>(parsedFilter);
        Assert.Equal(filter, parsedFilter.ToString());

        FilterNot actual = (FilterNot)parsedFilter;
        Assert.IsType<FilterNot>(actual.Filter);

        actual = (FilterNot)actual.Filter;
        Assert.Equal("foo", ((FilterEquality)actual.Filter).Attribute);
        Assert.Equal("bar", Encoding.UTF8.GetString(((FilterEquality)actual.Filter).Value.Span));
    }

    [Fact]
    public void FilterNotToBytes()
    {
        const string expected = "og6iDKMKBANmb28EA2Jhcg==";

        const string filter = "(!(!(foo=bar)))";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void InvalidFilterNotMultiple()
    {
        const string filter = "(!(objectClass=*)(foo=bar))";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Multiple filters found for not '!' expression", ex.Message);
        Assert.Equal(1, ex.StartPosition);
        Assert.Equal(26, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterNotNotStarted()
    {
        const string filter = "(!objectClass=*)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Expecting '(' to start after qualifier in complex filter expression", ex.Message);
        Assert.Equal(2, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }

    [Fact]
    public void InvalidFilterNotNoValue()
    {
        const string filter = "(!)";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("No filter value found after conditional", ex.Message);
        Assert.Equal(1, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }
}

public class LDAPFilterEqualityTests
{
    [Theory]
    [InlineData("objectClass=user", "objectClass", "user")]
    [InlineData("(objectClass=user)", "objectClass", "user")]
    [InlineData("objectClass;test=abc\\20def", "objectClass;test", "abc def")]
    public void EqualityFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterEquality>(parsedFilter);
        Assert.Equal(attribute, ((FilterEquality)parsedFilter).Attribute);
        Assert.Equal(value, Encoding.UTF8.GetString(((FilterEquality)parsedFilter).Value.Span));
    }

    [Fact]
    public void FilterEqualityToBytes()
    {
        const string expected = "oyUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void EqualityToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo=happy\\20☺ café\\2a");

        Assert.Equal("(foo=happy \\e2\\98\\ba caf\\c3\\a9\\2a)", filter.ToString());
    }
}

public class LDAPFilterSubstringsTests
{
    [Theory]
    [InlineData("attr=test*value", "attr", "test", new string[0], "value", false)]
    [InlineData("attr=test*value", "attr", "test", new string[0], "value", true)]
    [InlineData("attr=test*", "attr", "test", new string[0], null, false)]
    [InlineData("attr=test*", "attr", "test", new string[0], null, true)]
    [InlineData("attr=*test", "attr", null, new string[0], "test", false)]
    [InlineData("attr=*test", "attr", null, new string[0], "test", true)]
    [InlineData("attr=initial*any*final", "attr", "initial", new[] { "any" }, "final", false)]
    [InlineData("attr=initial*any*final", "attr", "initial", new[] { "any" }, "final", true)]
    [InlineData("attr=*any1*any2*", "attr", null, new[] { "any1", "any2" }, null, false)]
    [InlineData("attr=*any1*any2*", "attr", null, new[] { "any1", "any2" }, null, true)]
    [InlineData("attr=initial*any1*any2*", "attr", "initial", new[] { "any1", "any2" }, null, false)]
    [InlineData("attr=initial*any1*any2*", "attr", "initial", new[] { "any1", "any2" }, null, true)]
    [InlineData("attr=*any1*any2*final", "attr", null, new[] { "any1", "any2" }, "final", false)]
    [InlineData("attr=*any1*any2*final", "attr", null, new[] { "any1", "any2" }, "final", true)]
    [InlineData("attr=initial*any1*any2*final", "attr", "initial", new[] { "any1", "any2" }, "final", false)]
    [InlineData("attr=initial*any1*any2*final", "attr", "initial", new[] { "any1", "any2" }, "final", true)]
    public void SubstringsFilter(string filter, string attribute, string? initial, string[] any, string? final,
        bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterSubstrings>(parsedFilter);

        FilterSubstrings filterSubstrings = (FilterSubstrings)parsedFilter;
        string? actualInitial = null;
        if (filterSubstrings.Initial != null)
            actualInitial = Encoding.UTF8.GetString(filterSubstrings.Initial?.ToArray() ?? Array.Empty<byte>());

        string[] actualAny = filterSubstrings.Any.Select(v => Encoding.UTF8.GetString(v.Span)).ToArray();

        string? actualFinal = null;
        if (filterSubstrings.Final != null)
            actualFinal = Encoding.UTF8.GetString(filterSubstrings.Final?.ToArray() ?? Array.Empty<byte>());

        Assert.Equal(attribute, filterSubstrings.Attribute);
        Assert.Equal(initial, actualInitial);
        Assert.Equal(any, actualAny);
        Assert.Equal(final, actualFinal);
    }

    [Theory]
    [InlineData("objectClass;test=*abc\\20*def ☺ *café*",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCBBWNhZsOp")]
    [InlineData("objectClass;test=abc\\20*def ☺ *café*",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4AEYWJjIIEIZGVmIOKYuiCBBWNhZsOp")]
    [InlineData("objectClass;test=*abc\\20*def ☺ *café",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4EEYWJjIIEIZGVmIOKYuiCCBWNhZsOp")]
    [InlineData("objectClass;test=abc\\20*def ☺ *café",
        "pCsEEG9iamVjdENsYXNzO3Rlc3QwF4AEYWJjIIEIZGVmIOKYuiCCBWNhZsOp")]
    public void FilterSubstringsToBytes(string filter, string expected)
    {
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("attr=**", 6, 7, false)]
    [InlineData("attr=**", 7, 8, true)]
    [InlineData("attr=test**remaining", 10, 11, false)]
    [InlineData("attr=test**remaining", 11, 12, true)]
    public void InvalidSubstringsTwoAsterisks(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Cannot have 2 consecutive '*' in substring filter", ex.Message);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData("foo=*happy\\20☺*café\\2a*", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [InlineData("(foo=*happy\\20☺*café\\2a*)", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [InlineData("foo=happy\\20☺*café\\2a*", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [InlineData("(foo=happy\\20☺*café\\2a*)", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a*)")]
    [InlineData("foo=*happy\\20☺*café\\2a", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    [InlineData("(foo=*happy\\20☺*café\\2a)", "(foo=*happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    [InlineData("foo=happy\\20☺*café\\2a", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    [InlineData("(foo=happy\\20☺*café\\2a)", "(foo=happy \\e2\\98\\ba*caf\\c3\\a9\\2a)")]
    public void SubstringsToString(string filter, string expected)
    {
        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.Equal(expected, actual.ToString());
    }
}

public class LDAPFilterGreaterOrEqualTests
{
    [Theory]
    [InlineData("objectClass>=user", "objectClass", "user")]
    [InlineData("(objectClass>=user)", "objectClass", "user")]
    [InlineData("objectClass;test>=\\20abcdef", "objectClass;test", " abcdef")]
    public void GreaterOrEqualFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterGreaterOrEqual>(parsedFilter);
        Assert.Equal(attribute, ((FilterGreaterOrEqual)parsedFilter).Attribute);
        Assert.Equal(value, Encoding.UTF8.GetString(((FilterGreaterOrEqual)parsedFilter).Value.Span));
    }

    [Fact]
    public void FilterGreaterOrEqualToBytes()
    {
        const string expected = "pSUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test>=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void GreaterOrEqualToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo>=happy\\20☺ café\\2a");

        Assert.Equal("(foo>=happy \\e2\\98\\ba caf\\c3\\a9\\2a)", filter.ToString());
    }
}

public class LDAPFilterLessOrEqualTests
{
    [Theory]
    [InlineData("objectClass<=user", "objectClass", "user")]
    [InlineData("(objectClass<=user)", "objectClass", "user")]
    [InlineData("objectClass;test<=abcdef\\20", "objectClass;test", "abcdef ")]
    public void LessOrEqualFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterLessOrEqual>(parsedFilter);
        Assert.Equal(attribute, ((FilterLessOrEqual)parsedFilter).Attribute);
        Assert.Equal(value, Encoding.UTF8.GetString(((FilterLessOrEqual)parsedFilter).Value.Span));
    }

    [Fact]
    public void FilterLessOrEqualToBytes()
    {
        const string expected = "piUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test<=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void LessOrEqualToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo<=happy\\20☺ café\\2a");

        Assert.Equal("(foo<=happy \\e2\\98\\ba caf\\c3\\a9\\2a)", filter.ToString());
    }
}

public class LDAPFilterPresentTests
{
    [Theory]
    [InlineData("objectClass", false)]
    [InlineData("objectClass", true)]
    [InlineData("1.2.3.4.12912", false)]
    [InlineData("1.2.3.4.12912", true)]
    public void PresentFilter(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }

    [Fact]
    public void FilterPresentToBytes()
    {
        const string expected = "hxIxLjIuMy4zNDEuMC4xO3Rlc3Q=";

        const string filter = "1.2.3.341.0.1;test=*";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void PresentToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo=*");

        Assert.Equal("(foo=*)", filter.ToString());
    }
}

public class LDAPFilterApproxMatchTests
{
    [Theory]
    [InlineData("objectClass~=user", "objectClass", "user")]
    [InlineData("(objectClass~=user)", "objectClass", "user")]
    [InlineData("objectClass;test~=abc\\20\\2adef", "objectClass;test", "abc *def")]
    public void ApproxMatchFilter(string filter, string attribute, string value)
    {
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterApproxMatch>(parsedFilter);
        Assert.Equal(attribute, ((FilterApproxMatch)parsedFilter).Attribute);
        Assert.Equal(value, Encoding.UTF8.GetString(((FilterApproxMatch)parsedFilter).Value.Span));
    }

    [Fact]
    public void FilterApproxMatchToBytes()
    {
        const string expected = "qCUEEG9iamVjdENsYXNzO3Rlc3QEEWFiYyBkZWYg4pi6IGNhZsOp";

        const string filter = "objectClass;test~=abc\\20def ☺ café";
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ApproxMatchToString()
    {
        LDAPFilter filter = LDAPFilter.ParseFilter("foo~=happy\\20☺ café\\2a");

        Assert.Equal("(foo~=happy \\e2\\98\\ba caf\\c3\\a9\\2a)", filter.ToString());
    }
}

public class LDAPFilterExtensibleMatchTests
{
    [Theory]
    [InlineData("attr:=value", null, "attr", "value", false, false)]
    [InlineData("attr:=value", null, "attr", "value", false, true)]
    [InlineData("0:=value", null, "0", "value", false, false)]
    [InlineData("0:=value", null, "0", "value", false, true)]
    [InlineData("1.2:=value", null, "1.2", "value", false, false)]
    [InlineData("1.2:=value", null, "1.2", "value", false, true)]
    [InlineData("4.0.58;option:=value", null, "4.0.58;option", "value", false, false)]
    [InlineData("4.0.58;option:=value", null, "4.0.58;option", "value", false, true)]
    [InlineData("attr:dn:=value", null, "attr", "value", true, false)]
    [InlineData("attr:dn:=value", null, "attr", "value", true, true)]
    [InlineData("8.54.35;option:dn:=value", null, "8.54.35;option", "value", true, false)]
    [InlineData("8.54.35;option:dn:=value", null, "8.54.35;option", "value", true, true)]
    [InlineData("attr:rule:=value", "rule", "attr", "value", false, false)]
    [InlineData("attr:rule:=value", "rule", "attr", "value", false, true)]
    [InlineData("attr:dn:rule:=value", "rule", "attr", "value", true, false)]
    [InlineData("attr:dn:rule:=value", "rule", "attr", "value", true, true)]
    [InlineData("attr:dn:rule;option1:=value", "rule;option1", "attr", "value", true, false)]
    [InlineData("attr:dn:rule;option1:=value", "rule;option1", "attr", "value", true, true)]
    [InlineData("attr;opt:dn:rule;option1:=value", "rule;option1", "attr;opt", "value", true, false)]
    [InlineData("attr;opt:dn:rule;option1:=value", "rule;option1", "attr;opt", "value", true, true)]
    [InlineData(":rule:=value", "rule", null, "value", false, false)]
    [InlineData(":rule:=value", "rule", null, "value", false, true)]
    [InlineData(":0:=value", "0", null, "value", false, false)]
    [InlineData(":0:=value", "0", null, "value", false, true)]
    [InlineData(":0.1:=value", "0.1", null, "value", false, false)]
    [InlineData(":0.1:=value", "0.1", null, "value", false, true)]
    [InlineData(":9.0:=value", "9.0", null, "value", false, false)]
    [InlineData(":9.0:=value", "9.0", null, "value", false, true)]
    [InlineData(":3.84196.0.156:=value", "3.84196.0.156", null, "value", false, false)]
    [InlineData(":3.84196.0.156:=value", "3.84196.0.156", null, "value", false, true)]
    [InlineData(":dn:rule:=value", "rule", null, "value", true, false)]
    [InlineData(":dn:rule:=value", "rule", null, "value", true, true)]
    [InlineData(":dn:6.54.0.58:=value", "6.54.0.58", null, "value", true, false)]
    [InlineData(":dn:6.54.0.58:=value", "6.54.0.58", null, "value", true, true)]
    [InlineData(":rule;option1:=value", "rule;option1", null, "value", false, false)]
    [InlineData(":rule;option1:=value", "rule;option1", null, "value", false, true)]
    [InlineData(":rule;option1;option2:=value", "rule;option1;option2", null, "value", false, false)]
    [InlineData(":rule;option1;option2:=value", "rule;option1;option2", null, "value", false, true)]
    [InlineData(":1.2.548.6;option1;option2:=value", "1.2.548.6;option1;option2", null, "value", false, false)]
    [InlineData(":1.2.548.6;option1;option2:=value", "1.2.548.6;option1;option2", null, "value", false, true)]
    public void ExtensibleMatchFilter(string filter, string? matchingRule, string? attribute, string value,
        bool dnAttributes, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";
        LDAPFilter parsedFilter = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterExtensibleMatch>(parsedFilter);

        FilterExtensibleMatch filterExtensible = (FilterExtensibleMatch)parsedFilter;
        Assert.Equal(matchingRule, filterExtensible.MatchingRule);
        Assert.Equal(attribute, filterExtensible.Attribute);
        Assert.Equal(value, Encoding.UTF8.GetString(filterExtensible.Value.Span));
        Assert.Equal(dnAttributes, filterExtensible.DNAttributes);
    }

    [Theory]
    [InlineData(":=value", 0, 1, false)]
    [InlineData(":=value", 1, 2, true)]
    public void InvalidExtensibleNoValue(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Extensible filter must define an attribute and/or rule before ':='", ex.Message);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData("1attribute:=value", 0, 10, false)]
    [InlineData("1attribute:=value", 1, 11, true)]
    [InlineData("attr_value:=value", 0, 10, false)]
    [InlineData("attr_value:=value", 1, 11, true)]
    [InlineData("4.7.06.1:=value", 0, 8, false)]
    [InlineData("4.7.06.1:=value", 1, 9, true)]
    [InlineData("attr;option;:=value", 0, 12, false)]
    [InlineData("attr;option;:=value", 1, 13, true)]
    public void InvalidExtensibleInvalidAttribute(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Invalid extensible filter attribute value", ex.Message);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData("attr:1rule:=value", 5, 10, false)]
    [InlineData("attr:1rule:=value", 6, 11, true)]
    [InlineData("attr:dn:1rule:=value", 8, 13, false)]
    [InlineData("attr:dn:1rule:=value", 9, 14, true)]
    [InlineData("attr:rule_value:=value", 5, 15, false)]
    [InlineData("attr:rule_value:=value", 6, 16, true)]
    [InlineData("attr:4.7.06.1:=value", 5, 13, false)]
    [InlineData("attr:4.7.06.1:=value", 6, 14, true)]
    [InlineData("attr:rule;option;:=value", 5, 17, false)]
    [InlineData("attr:rule;option;:=value", 6, 18, true)]
    public void InvalidExtensibleInvalidRule(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Invalid extensible filter rule value", ex.Message);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData(":dn:=value", 0, 4, false)]
    [InlineData(":dn:=value", 1, 5, true)]
    public void InvalidExtensibleNoAttributeOrRule(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Extensible filter must define the attribute, rule, or both", ex.Message);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData("attr:rule:extra:=value", 10, 16, false)]
    [InlineData("attr:rule:extra:=value", 11, 17, true)]
    [InlineData("attr:dn:rule:extra:=value", 13, 19, false)]
    [InlineData("attr:dn:rule:extra:=value", 14, 20, true)]
    [InlineData(":rule:extra:=value", 6, 12, false)]
    [InlineData(":rule:extra:=value", 7, 13, true)]
    [InlineData(":dn:rule:extra:=value", 9, 15, false)]
    [InlineData(":dn:rule:extra:=value", 10, 16, true)]
    public void InvalidExtensibleExtraDataBeforeEquals(string filter, int expectedStart, int expectedEnd, bool wrapInParens)
    {
        if (wrapInParens) filter = $"({filter})";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Extra data found in extensible filter key", ex.Message);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Theory]
    [InlineData("foo:=happy\\20☺ café\\2a", "(foo:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [InlineData("(foo:=happy\\20☺ café\\2a)", "(foo:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [InlineData("foo:dn:=happy\\20☺ café\\2a", "(foo:dn:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [InlineData("(foo:dn:=happy\\20☺ café\\2a)", "(foo:dn:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [InlineData("foo:rule:=happy\\20☺ café\\2a", "(foo:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [InlineData("(foo:rule:=happy\\20☺ café\\2a)", "(foo:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [InlineData("foo:dn:rule:=happy\\20☺ café\\2a", "(foo:dn:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    [InlineData("(foo:dn:rule:=happy\\20☺ café\\2a)", "(foo:dn:rule:=happy \\e2\\98\\ba caf\\c3\\a9\\2a)")]
    public void ExtensibleToString(string filter, string expected)
    {
        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.Equal(expected, actual.ToString());
    }
}

public class LDAPFilterAttributeTests
{
    [Theory]
    [InlineData("objectClass", false)]
    [InlineData("objectClass", true)]
    [InlineData("sAMAccountName", false)]
    [InlineData("sAMAccountName", true)]
    [InlineData("Test-attr", false)]
    [InlineData("Test-attr", true)]
    [InlineData("test-", false)]
    [InlineData("test-", true)]
    [InlineData("test0", false)]
    [InlineData("test1", true)]
    public void AttributeAsString(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }

    [Theory]
    [InlineData("0", false)]
    [InlineData("0", true)]
    [InlineData("0.0", false)]
    [InlineData("0.0", true)]
    [InlineData("1.0.1", false)]
    [InlineData("1.0.1", true)]
    [InlineData("9.54", false)]
    [InlineData("9.54", true)]
    [InlineData("3.2.454.23436.1", false)]
    [InlineData("3.2.454.23436.1", true)]
    [InlineData("2.123434.1219214.4394", false)]
    [InlineData("2.123434.1219214.4394", true)]
    public void AttributeAsOID(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }

    [Theory]
    [InlineData("objectClass;option1", false)]
    [InlineData("objectClass;option1", true)]
    [InlineData("objectClass;option1;option-2", false)]
    [InlineData("objectClass;option1;option-2", true)]
    [InlineData("objectClass;1option", false)]
    [InlineData("objectClass;1option", true)]
    [InlineData("objectClass;-option", false)]
    [InlineData("objectClass;-option", true)]
    [InlineData("1.2.334.1293;option1", false)]
    [InlineData("1.2.334.1293;option1", true)]
    [InlineData("1.2.334.1293;option1;option-2", false)]
    [InlineData("1.2.334.1293;option1;option-2", true)]
    [InlineData("1.2.334.1293;1option", false)]
    [InlineData("1.2.334.1293;1option", true)]
    [InlineData("1.2.334.1293;-option", false)]
    [InlineData("1.2.334.1293;-option", true)]
    public void AttributeWithOption(string attribute, bool wrapInParens)
    {
        string filter = $"{attribute}=*";
        if (wrapInParens) filter = $"({filter})";

        LDAPFilter actual = LDAPFilter.ParseFilter(filter);

        Assert.IsType<FilterPresent>(actual);
        Assert.Equal(attribute, ((FilterPresent)actual).Attribute);
    }

    [Theory]
    [InlineData("1attribute=*", 0, 10)] // Must start with a letter
    [InlineData("(1attribute=*)", 1, 11)] // Same as above but wrapped in ()
    [InlineData("(attribute_test=*)", 1, 15)] // Can only contain letters, numbers and -
    [InlineData("1.02.2320=*", 0, 9)] // OID segment must not start with 0 unless it's 0 itself
    [InlineData("attribute;option;=*", 0, 17)] // Option must not end with ;
    public void InvalidAttribute(string filter, int expectedStart, int expectedEnd)
    {
        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Invalid filter attribute value", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }

    [Fact]
    public void InvalidSimpleFilterFormat()
    {
        const string filter = "=foo";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Simple filter value must not start with '='", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(1, ex.EndPosition);
    }

    [Fact]
    public void InvalidSimpleFilterNoEquals()
    {
        const string filter = "foo";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Simple filter missing '=' character", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(3, ex.EndPosition);
    }

    [Fact]
    public void InvalidSimpleFilterNoValue()
    {
        const string filter = "foo=";

        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.Equal("Simple filter value is not present after '='", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(0, ex.StartPosition);
        Assert.Equal(4, ex.EndPosition);
    }
}

public class LDAPFilterValueTests
{
    [Theory]
    [InlineData("simple_123", "simple_123")]
    [InlineData("café", "café")]
    [InlineData("test with space", "test with space")]
    [InlineData("null \\00", "null \0")]
    [InlineData("open paren \\28", "open paren (")]
    [InlineData("close paren \\29", "close paren )")]
    [InlineData("asterisk \\2a", "asterisk *")]
    [InlineData("backslash \\5C", "backslash \\")]
    [InlineData("any escaped \\20", "any escaped  ")]
    [InlineData("happy face \\e2\\98\\BA", "happy face ☺")]
    [InlineData("abc\\ax", "abc\\ax")]
    [InlineData("\\z3 testing", "\\z3 testing")]
    [InlineData("test\\a", "test\\a")]
    [InlineData("testing \\", "testing \\")]
    public void ParseSimpleValue(string value, string expected)
    {
        FilterEquality filter = (FilterEquality)LDAPFilter.ParseFilter($"foo={value}");

        string actual = Encoding.UTF8.GetString(filter.Value.Span);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("objectClass;test:=abc\\20 def ☺ café",
        "qSaCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqQ==")]
    [InlineData("objectClass;test:dn:=abc\\20 def ☺ café",
        "qSmCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqYQB/w==")]
    [InlineData("objectClass;test:rule:=abc\\20 def ☺ café",
        "qSyBBHJ1bGWCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqQ==")]
    [InlineData("objectClass;test:dn:rule:=abc\\20 def ☺ café",
        "qS+BBHJ1bGWCEG9iamVjdENsYXNzO3Rlc3SDEmFiYyAgZGVmIOKYuiBjYWbDqYQB/w==")]
    [InlineData(":rule:=abc\\20 def ☺ café",
        "qRqBBHJ1bGWDEmFiYyAgZGVmIOKYuiBjYWbDqQ==")]
    [InlineData(":dn:rule:=abc\\20 def ☺ café",
        "qR2BBHJ1bGWDEmFiYyAgZGVmIOKYuiBjYWbDqYQB/w==")]
    public void FilterSubstringsToBytes(string filter, string expected)
    {
        LDAPFilter parseFilter = LDAPFilter.ParseFilter(filter);
        AsnWriter writer = new(AsnEncodingRules.BER);
        parseFilter.ToBytes(writer);

        string actual = Convert.ToBase64String(writer.Encode());

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("foo=abc\0", 7, 8)]
    [InlineData("foo=ab(def", 6, 7)]
    public void UnescapedCharacter(string filter, int expectedStart, int expectedEnd)
    {
        var ex = Assert.Throws<InvalidLDAPFilterException>(() => LDAPFilter.ParseFilter(filter));

        Assert.StartsWith("LDAP filter value contained unescaped char", ex.Message);
        Assert.Equal(filter, ex.Filter);
        Assert.Equal(expectedStart, ex.StartPosition);
        Assert.Equal(expectedEnd, ex.EndPosition);
    }
}
