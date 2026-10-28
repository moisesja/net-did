using FluentAssertions;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Method.Key;

namespace NetDid.Method.Key.Tests;

/// <summary>
/// Regression coverage that `DefaultVerificationRelationshipResolver` agrees with what
/// `DidKeyMethod` actually populates per key type. did:key's relationship population is
/// key-type-specific (X25519 → keyAgreement only; BLS → assertionMethod + capabilityInvocation;
/// Ed25519 with derivation → all of the above) — this test locks that contract end-to-end.
/// </summary>
public class DidKeyVerificationRelationshipResolverTests
{
    private readonly DidKeyMethod _method = new(new DefaultKeyGenerator());

    /// <summary>Adapter: route any DID into the local DidKeyMethod resolver.</summary>
    private sealed class DidKeyOnlyResolver : IDidResolver
    {
        private readonly DidKeyMethod _method;
        public DidKeyOnlyResolver(DidKeyMethod method) => _method = method;

        public Task<DidResolutionResult> ResolveAsync(
            string did, DidResolutionOptions? options = null, CancellationToken ct = default)
            => _method.ResolveAsync(did, options, ct);

        public bool CanResolve(string did) => did.StartsWith("did:key:", StringComparison.Ordinal);
    }

    private async Task<(string Did, string VmId)> CreateDidKeyAsync(KeyType keyType)
    {
        var result = await _method.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = keyType,
            EnableEncryptionKeyDerivation = true
        });
        var doc = result.DidDocument!;
        // First VM is the canonical key for that DID
        var vmId = doc.VerificationMethod![0].Id;
        return (result.Did.Value!, vmId);
    }

    private DefaultVerificationRelationshipResolver Sut() =>
        new(new DidKeyOnlyResolver(_method));

    [Theory]
    [InlineData(VerificationRelationship.Authentication)]
    [InlineData(VerificationRelationship.AssertionMethod)]
    [InlineData(VerificationRelationship.CapabilityInvocation)]
    [InlineData(VerificationRelationship.CapabilityDelegation)]
    public async Task Ed25519_PrimaryVm_AuthorizedForSigningRelationships(VerificationRelationship relationship)
    {
        var (did, vmId) = await CreateDidKeyAsync(KeyType.Ed25519);
        var sut = Sut();

        var result = await sut.IsAuthorizedForRelationshipAsync(did, vmId, relationship);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
    }

    [Fact]
    public async Task Ed25519_PrimaryVm_NotAuthorizedForKeyAgreement()
    {
        // KeyAgreement gets the derived X25519 entry, not the Ed25519 signing VM
        var (did, vmId) = await CreateDidKeyAsync(KeyType.Ed25519);
        var sut = Sut();

        var result = await sut.IsAuthorizedForRelationshipAsync(
            did, vmId, VerificationRelationship.KeyAgreement);

        result.Decision.Should().Be(AuthorizationDecision.NotAuthorized);
    }

    [Theory]
    [InlineData(VerificationRelationship.Authentication)]
    [InlineData(VerificationRelationship.AssertionMethod)]
    [InlineData(VerificationRelationship.CapabilityInvocation)]
    [InlineData(VerificationRelationship.CapabilityDelegation)]
    public async Task X25519_PrimaryVm_NotAuthorizedForSigningRelationships(VerificationRelationship relationship)
    {
        var (did, vmId) = await CreateDidKeyAsync(KeyType.X25519);
        var sut = Sut();

        var result = await sut.IsAuthorizedForRelationshipAsync(did, vmId, relationship);

        result.Decision.Should().Be(AuthorizationDecision.NotAuthorized);
    }

    [Fact]
    public async Task X25519_PrimaryVm_AuthorizedForKeyAgreementOnly()
    {
        var (did, vmId) = await CreateDidKeyAsync(KeyType.X25519);
        var sut = Sut();

        var result = await sut.IsAuthorizedForRelationshipAsync(
            did, vmId, VerificationRelationship.KeyAgreement);

        result.Decision.Should().Be(AuthorizationDecision.Authorized);
    }
}
