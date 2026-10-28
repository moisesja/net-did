using FluentAssertions;
using NetCid;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

public class ScidGeneratorTests
{
    [Fact]
    public void ComputeScid_KnownAnswer_ProducesBareSha256Multihash()
    {
        var json = """
            {"parameters":{"method":"did:webvh:1.0","scid":"{SCID}"},"state":{"id":"did:webvh:{SCID}:example.com"},"versionId":"{SCID}","versionTime":"2025-01-01T00:00:00Z"}
            """;
        var scid1 = ScidGenerator.ComputeScid(json);
        var scid2 = ScidGenerator.ComputeScid(json);

        scid1.Should().Be(scid2);
        scid1.Should().Be("QmSFSmtvxAXzZMWWsgdV6qyixGP4gXgqCfzMt9fEppvcZh");
        AssertBareSha256Multihash(
            scid1,
            "3a19595e2aeb5359506c33aa88654a4991d5a0d92e7f985e986f9c9e2c114a2c");
    }

    [Fact]
    public void ComputeScid_DifferentInput_DifferentResult()
    {
        var json1 = """{"versionId":"{SCID}","parameters":{"scid":"{SCID}","key":"a"}}""";
        var json2 = """{"versionId":"{SCID}","parameters":{"scid":"{SCID}","key":"b"}}""";

        var scid1 = ScidGenerator.ComputeScid(json1);
        var scid2 = ScidGenerator.ComputeScid(json2);

        scid1.Should().NotBe(scid2);
    }

    [Fact]
    public void ReplacePlaceholders_ReplacesAll()
    {
        var json = """{"id":"did:webvh:{SCID}:example.com","scid":"{SCID}","versionId":"{SCID}"}""";
        var result = ScidGenerator.ReplacePlaceholders(json, "QmTest123");

        result.Should().NotContain("{SCID}");
        result.Should().Contain("QmTest123");
        // Should have replaced 3 occurrences
        result.Split("QmTest123").Length.Should().Be(4); // 3 replacements = 4 parts
    }

    [Fact]
    public void ComputeEntryHash_KnownAnswer_ProducesBareSha256Multihash()
    {
        var json = """{"versionId":"1-test","parameters":{}}""";
        var hash1 = ScidGenerator.ComputeEntryHash(json);
        var hash2 = ScidGenerator.ComputeEntryHash(json);

        hash1.Should().Be(hash2);
        hash1.Should().Be("QmWzeLrRMgUWwQt8UFqERUCgLTNPq3nVgojRptAVdpf547");
        AssertBareSha256Multihash(
            hash1,
            "809926dd6a85d6b9947384b5547d3c26e80b1dcdef1a141f761f38d29e08fe24");
    }

    private static void AssertBareSha256Multihash(string value, string expectedDigestHex)
    {
        value.Should().HaveLength(46);
        value.Should().NotStartWith("z");

        var wireBytes = Multibase.Decode($"z{value}");
        wireBytes.Should().HaveCount(34);
        wireBytes[0].Should().Be(0x12);
        wireBytes[1].Should().Be(0x20);

        Multihash.TryDecode(wireBytes, out var code, out var digest).Should().BeTrue();
        code.Should().Be(MultihashCode.Sha2_256);
        digest.Should().Equal(Convert.FromHexString(expectedDigestHex));
    }
}
