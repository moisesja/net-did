using FluentAssertions;
using NetDid.Core.Model;

namespace NetDid.Core.Tests.Model;

public class VerificationRelationshipEntryTests
{
    [Fact]
    public void FromReference_CreatesReferenceEntry()
    {
        var entry = VerificationRelationshipEntry.FromReference("did:key:z6Mk#key-1");

        entry.IsReference.Should().BeTrue();
        entry.Reference.Should().Be("did:key:z6Mk#key-1");
        entry.EmbeddedMethod.Should().BeNull();
    }

    [Fact]
    public void FromEmbedded_CreatesEmbeddedEntry()
    {
        var vm = new VerificationMethod
        {
            Id = "did:key:z6Mk#key-1",
            Type = "Multikey",
            Controller = new Did("did:key:z6Mk")
        };
        var entry = VerificationRelationshipEntry.FromEmbedded(vm);

        entry.IsReference.Should().BeFalse();
        entry.Reference.Should().BeNull();
        entry.EmbeddedMethod.Should().NotBeNull();
    }

    [Fact]
    public void FromReference_NullOrEmpty_ThrowsArgumentException()
    {
        var act = () => VerificationRelationshipEntry.FromReference("");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void FromEmbedded_Null_ThrowsArgumentNullException()
    {
        var act = () => VerificationRelationshipEntry.FromEmbedded(null!);
        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void ImplicitConversionFromString_CreatesReference()
    {
        VerificationRelationshipEntry entry = "did:key:z6Mk#key-1";
        entry.IsReference.Should().BeTrue();
        entry.Reference.Should().Be("did:key:z6Mk#key-1");
    }
}
