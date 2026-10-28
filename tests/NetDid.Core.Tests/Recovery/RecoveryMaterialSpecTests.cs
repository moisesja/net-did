using FluentAssertions;
using NetDid.Core.Recovery;

namespace NetDid.Core.Tests.Recovery;

public class RecoveryMaterialSpecTests
{
    [Fact]
    public void Constructor_AssignsAllProperties()
    {
        var spec = new RecoveryMaterialSpec(
            Kind: "webvh-log-commitment",
            SchemaVersion: 1,
            Encoding: "application/json");

        spec.Kind.Should().Be("webvh-log-commitment");
        spec.SchemaVersion.Should().Be(1);
        spec.Encoding.Should().Be("application/json");
    }

    [Fact]
    public void Equality_IsValueBased()
    {
        var a = new RecoveryMaterialSpec("k", 1, "e");
        var b = new RecoveryMaterialSpec("k", 1, "e");
        var c = new RecoveryMaterialSpec("k", 2, "e");

        a.Should().Be(b);
        a.Should().NotBe(c);
    }

    [Fact]
    public void WithExpression_ProducesNewInstance()
    {
        var v1 = new RecoveryMaterialSpec("k", 1, "e");
        var v2 = v1 with { SchemaVersion = 2 };

        v2.Kind.Should().Be("k");
        v2.SchemaVersion.Should().Be(2);
        v2.Encoding.Should().Be("e");
        v1.SchemaVersion.Should().Be(1);
    }
}
