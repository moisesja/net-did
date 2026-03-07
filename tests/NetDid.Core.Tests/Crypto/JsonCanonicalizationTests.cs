using FluentAssertions;
using NetDid.Core.Crypto.Jcs;

namespace NetDid.Core.Tests.Crypto;

public class JsonCanonicalizationTests
{
    [Fact]
    public void Canonicalize_SortsProperties()
    {
        var json = """{"z":"last","a":"first","m":"middle"}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"a":"first","m":"middle","z":"last"}""");
    }

    [Fact]
    public void Canonicalize_NestedObject_SortedRecursively()
    {
        var json = """{"b":{"z":1,"a":2},"a":"first"}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"a":"first","b":{"a":2,"z":1}}""");
    }

    [Fact]
    public void Canonicalize_Array_PreservesOrder()
    {
        var json = """[3,1,2]""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("[3,1,2]");
    }

    [Fact]
    public void Canonicalize_Integer_NoDecimalPoint()
    {
        var json = """{"value":42}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":42}""");
    }

    [Fact]
    public void Canonicalize_Zero_NoDecimalPoint()
    {
        var json = """{"value":0}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":0}""");
    }

    [Fact]
    public void Canonicalize_NegativeInteger()
    {
        var json = """{"value":-5}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":-5}""");
    }

    [Fact]
    public void Canonicalize_FloatingPoint()
    {
        var json = """{"value":1.5}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":1.5}""");
    }

    [Fact]
    public void Canonicalize_Boolean_True()
    {
        var json = """{"value":true}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":true}""");
    }

    [Fact]
    public void Canonicalize_Boolean_False()
    {
        var json = """{"value":false}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":false}""");
    }

    [Fact]
    public void Canonicalize_Null()
    {
        var json = """{"value":null}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":null}""");
    }

    [Fact]
    public void Canonicalize_StringEscaping_Backslash()
    {
        var json = """{"value":"a\\b"}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":"a\\b"}""");
    }

    [Fact]
    public void Canonicalize_StringEscaping_Quotes()
    {
        var json = """{"value":"say \"hello\""}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":"say \"hello\""}""");
    }

    [Fact]
    public void Canonicalize_StringEscaping_ControlCharacters()
    {
        var json = """{"value":"line1\nline2\ttab"}""";
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"value":"line1\nline2\ttab"}""");
    }

    [Fact]
    public void Canonicalize_EmptyObject()
    {
        var result = JsonCanonicalization.Canonicalize("{}");
        result.Should().Be("{}");
    }

    [Fact]
    public void Canonicalize_EmptyArray()
    {
        var result = JsonCanonicalization.Canonicalize("[]");
        result.Should().Be("[]");
    }

    [Fact]
    public void Canonicalize_NoWhitespace()
    {
        var json = """
        {
            "b" : 2 ,
            "a" : 1
        }
        """;
        var result = JsonCanonicalization.Canonicalize(json);

        result.Should().Be("""{"a":1,"b":2}""");
    }

    [Fact]
    public void CanonicalizeToUtf8_ReturnsValidBytes()
    {
        var json = """{"a":1}""";
        var bytes = JsonCanonicalization.CanonicalizeToUtf8(json);

        var str = System.Text.Encoding.UTF8.GetString(bytes);
        str.Should().Be("""{"a":1}""");
    }

    [Fact]
    public void FormatEs6Number_LargeInteger()
    {
        var result = JsonCanonicalization.FormatEs6Number(1e20);
        result.Should().Be("100000000000000000000");
    }

    [Fact]
    public void FormatEs6Number_NegativeZero()
    {
        var result = JsonCanonicalization.FormatEs6Number(-0.0);
        result.Should().Be("-0");
    }

    [Fact]
    public void FormatEs6Number_PositiveZero()
    {
        var result = JsonCanonicalization.FormatEs6Number(0.0);
        result.Should().Be("0");
    }

    [Fact]
    public void Canonicalize_Rfc8785_TestVector_PropertySorting()
    {
        // RFC 8785 §3.2.3 test: properties sorted by Unicode code points
        var json = """{"peach":"This Sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"follow the rules in RFC 8785"}""";
        var result = JsonCanonicalization.Canonicalize(json);

        // Sorted by raw Unicode code point comparison
        result.Should().StartWith("""{"peach":""");
    }
}
