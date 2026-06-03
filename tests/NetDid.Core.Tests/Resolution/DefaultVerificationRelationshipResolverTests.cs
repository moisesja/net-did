using FluentAssertions;
using NSubstitute;
using NetDid.Core.Model;
using NetDid.Core.Resolution;

namespace NetDid.Core.Tests.Resolution;

public class DefaultVerificationRelationshipResolverTests
{
    private const string ControllerDid = "did:example:ctrl";

    private readonly IDidResolver _didResolver;
    private readonly DefaultVerificationRelationshipResolver _sut;

    public DefaultVerificationRelationshipResolverTests()
    {
        _didResolver = Substitute.For<IDidResolver>();
        _sut = new DefaultVerificationRelationshipResolver(_didResolver);
    }

    private void SetupResolver(DidDocument doc)
    {
        _didResolver.ResolveAsync(Arg.Any<string>(), Arg.Any<DidResolutionOptions?>(), Arg.Any<CancellationToken>())
            .Returns(new DidResolutionResult
            {
                DidDocument = doc,
                ResolutionMetadata = new DidResolutionMetadata { ContentType = DidContentTypes.JsonLd }
            });
    }

    private void SetupResolverError(DidResolutionResult error)
    {
        _didResolver.ResolveAsync(Arg.Any<string>(), Arg.Any<DidResolutionOptions?>(), Arg.Any<CancellationToken>())
            .Returns(error);
    }

    private static DidDocument DocWith(
        VerificationRelationship relationship,
        params VerificationRelationshipEntry[] entries)
    {
        IReadOnlyList<VerificationRelationshipEntry> list = entries;
        return relationship switch
        {
            VerificationRelationship.Authentication => new DidDocument
                { Id = new Did(ControllerDid), Authentication = list },
            VerificationRelationship.AssertionMethod => new DidDocument
                { Id = new Did(ControllerDid), AssertionMethod = list },
            VerificationRelationship.KeyAgreement => new DidDocument
                { Id = new Did(ControllerDid), KeyAgreement = list },
            VerificationRelationship.CapabilityInvocation => new DidDocument
                { Id = new Did(ControllerDid), CapabilityInvocation = list },
            VerificationRelationship.CapabilityDelegation => new DidDocument
                { Id = new Did(ControllerDid), CapabilityDelegation = list },
            _ => throw new ArgumentOutOfRangeException(nameof(relationship))
        };
    }

    // Case 1 — Cross-DID reference (Issue Break A)
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_CrossDidReference_Authorized()
    {
        SetupResolver(DocWith(
            VerificationRelationship.CapabilityInvocation,
            VerificationRelationshipEntry.FromReference("did:web:alice.example#key-1")));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, "did:web:alice.example#key-1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
    }

    // Case 2 — Relationship discrimination (Issue Break B)
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_WrongRelationship_NotAuthorized()
    {
        SetupResolver(DocWith(
            VerificationRelationship.CapabilityInvocation,
            VerificationRelationshipEntry.FromReference($"{ControllerDid}#hot")));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#hot", VerificationRelationship.CapabilityDelegation);

        result.Decision.Should().Be(AuthorizationDecision.NotAuthorized);
    }

    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_BothRelationshipsListed_BothAuthorized()
    {
        var vmId = $"{ControllerDid}#k1";
        SetupResolver(new DidDocument
        {
            Id = new Did(ControllerDid),
            CapabilityInvocation = new[] { VerificationRelationshipEntry.FromReference(vmId) },
            CapabilityDelegation = new[] { VerificationRelationshipEntry.FromReference(vmId) }
        });

        var inv = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, vmId, VerificationRelationship.CapabilityInvocation);
        var del = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, vmId, VerificationRelationship.CapabilityDelegation);

        inv.Decision.Should().Be(AuthorizationDecision.Authorized);
        del.Decision.Should().Be(AuthorizationDecision.Authorized);
    }

    // Case 3 — Embedded entry match by EmbeddedMethod.Id
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_EmbeddedEntry_Authorized()
    {
        var vmId = $"{ControllerDid}#embedded";
        var vm = new VerificationMethod
        {
            Id = vmId,
            Type = "Multikey",
            Controller = new Did(ControllerDid),
            PublicKeyMultibase = "z6Mk..."
        };
        SetupResolver(DocWith(
            VerificationRelationship.CapabilityInvocation,
            VerificationRelationshipEntry.FromEmbedded(vm)));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, vmId, VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
    }

    // Case 4 — Normalization, fragment-only entry
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_FragmentOnlyEntry_NormalizesAndMatches()
    {
        SetupResolver(DocWith(
            VerificationRelationship.AssertionMethod,
            VerificationRelationshipEntry.FromReference("#k1")));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#k1", VerificationRelationship.AssertionMethod);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
    }

    // Case 5 — Normalization, bare id entry (no colon, no hash)
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_BareIdEntry_NormalizesAndMatches()
    {
        SetupResolver(DocWith(
            VerificationRelationship.AssertionMethod,
            VerificationRelationshipEntry.FromReference("k1")));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#k1", VerificationRelationship.AssertionMethod);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
    }

    // Case 6 — Relationship empty or absent
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_RelationshipAbsent_NotAuthorized()
    {
        SetupResolver(new DidDocument { Id = new Did(ControllerDid) });

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#k1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.NotAuthorized);
        result.ResolutionError.Should().BeNull();
    }

    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_EmptyRelationshipList_NotAuthorized()
    {
        SetupResolver(new DidDocument
        {
            Id = new Did(ControllerDid),
            CapabilityInvocation = Array.Empty<VerificationRelationshipEntry>()
        });

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#k1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.NotAuthorized);
    }

    // Case 7 — Resolution failures keep the cause visible
    [Theory]
    [InlineData("notFound")]
    [InlineData("invalidDid")]
    [InlineData("methodNotSupported")]
    public async Task IsAuthorizedForRelationshipAsync_ResolutionFailure_ReturnsNotResolvableWithError(string error)
    {
        SetupResolverError(new DidResolutionResult
        {
            DidDocument = null,
            ResolutionMetadata = new DidResolutionMetadata { Error = error }
        });

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#k1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.ControllerNotResolvable);
        result.ResolutionError.Should().Be(error);
        result.Message.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_ResolutionFailureWithoutErrorCode_DefaultsToNotFound()
    {
        SetupResolverError(new DidResolutionResult
        {
            DidDocument = null,
            ResolutionMetadata = new DidResolutionMetadata()
        });

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#k1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.ControllerNotResolvable);
        result.ResolutionError.Should().Be("notFound");
    }

    // Case 9 — Wrong controller / normalized mismatch
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_AbsoluteForeignReference_AuthorizesUnderControllerA()
    {
        SetupResolver(DocWith(
            VerificationRelationship.CapabilityInvocation,
            VerificationRelationshipEntry.FromReference("did:example:B#k1")));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, "did:example:B#k1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
    }

    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_RelativeEntry_DoesNotMatchForeignVm()
    {
        SetupResolver(DocWith(
            VerificationRelationship.CapabilityInvocation,
            VerificationRelationshipEntry.FromReference("#k1")));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, "did:example:B#k1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.NotAuthorized);
    }

    // Limitation we test on purpose — exact ordinal match, no query stripping
    [Fact]
    public async Task IsAuthorizedForRelationshipAsync_EntryWithQueryParam_DoesNotMatchBareVm()
    {
        SetupResolver(DocWith(
            VerificationRelationship.CapabilityInvocation,
            VerificationRelationshipEntry.FromReference($"{ControllerDid}#k1?versionId=1")));

        var result = await _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, $"{ControllerDid}#k1", VerificationRelationship.CapabilityInvocation);

        result.Decision.Should().Be(AuthorizationDecision.NotAuthorized);
    }

    // Case 10 — Argument guards
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task IsAuthorizedForRelationshipAsync_BadControllerDid_Throws(string? controllerDid)
    {
        var act = () => _sut.IsAuthorizedForRelationshipAsync(
            controllerDid!, $"{ControllerDid}#k1", VerificationRelationship.CapabilityInvocation);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task IsAuthorizedForRelationshipAsync_BadVmDidUrl_Throws(string? vmDidUrl)
    {
        var act = () => _sut.IsAuthorizedForRelationshipAsync(
            ControllerDid, vmDidUrl!, VerificationRelationship.CapabilityInvocation);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public void Constructor_NullResolver_Throws()
    {
        var act = () => new DefaultVerificationRelationshipResolver(null!);
        act.Should().Throw<ArgumentNullException>();
    }
}
