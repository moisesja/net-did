using FluentAssertions;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

public class ScidGeneratorTests
{
    [Fact]
    public void ComputeScid_Deterministic()
    {
        var json = """{"versionId":"1-{SCID}","parameters":{"scid":"{SCID}"}}""";
        var scid1 = ScidGenerator.ComputeScid(json);
        var scid2 = ScidGenerator.ComputeScid(json);

        scid1.Should().Be(scid2);
        scid1.Should().StartWith("z"); // Base58Btc multibase prefix
    }

    [Fact]
    public void ComputeScid_DifferentInput_DifferentResult()
    {
        var json1 = """{"versionId":"1-{SCID}","parameters":{"scid":"{SCID}","key":"a"}}""";
        var json2 = """{"versionId":"1-{SCID}","parameters":{"scid":"{SCID}","key":"b"}}""";

        var scid1 = ScidGenerator.ComputeScid(json1);
        var scid2 = ScidGenerator.ComputeScid(json2);

        scid1.Should().NotBe(scid2);
    }

    [Fact]
    public void ReplacePlaceholders_ReplacesAll()
    {
        var json = """{"id":"did:webvh:{SCID}:example.com","scid":"{SCID}","versionId":"1-{SCID}"}""";
        var result = ScidGenerator.ReplacePlaceholders(json, "QmTest123");

        result.Should().NotContain("{SCID}");
        result.Should().Contain("QmTest123");
        // Should have replaced 3 occurrences
        result.Split("QmTest123").Length.Should().Be(4); // 3 replacements = 4 parts
    }

    [Fact]
    public void ComputeEntryHash_Deterministic()
    {
        var json = """{"versionId":"1-test","parameters":{}}""";
        var hash1 = ScidGenerator.ComputeEntryHash(json);
        var hash2 = ScidGenerator.ComputeEntryHash(json);

        hash1.Should().Be(hash2);
        hash1.Should().StartWith("z");
    }
}
