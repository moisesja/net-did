using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Deployment;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Provenance pinning for the vendored ERC-1056 registry creation bytecode.
/// The expected keccak256 digests were computed with an INDEPENDENT implementation
/// (pycryptodome) over the artifacts as published on npm, so this test simultaneously
/// pins the embedded bytes against drift and cross-checks NetCrypto's Keccak256
/// against an external oracle.
/// </summary>
public class Erc1056RegistryTests
{
    [Fact]
    public void ModernCreationBytecode_MatchesThePublishedNpmArtifact()
    {
        // ethr-did-registry@1.3.0 → artifacts/.../EthereumDIDRegistry.json → bytecode
        var bytecode = Erc1056Registry.ModernCreationBytecode;

        bytecode.Length.Should().Be(5096);
        Convert.ToHexString(Keccak256.Hash(bytecode.Span)).ToLowerInvariant()
            .Should().Be("804b15fb5bacfda62e75154685fac861d65c2a5811d0379a8b60221cf6b8e6e4");
    }

    [Fact]
    public void LegacyCreationBytecode_MatchesThePublishedNpmArtifact()
    {
        // ethr-did-registry@0.0.3 → build/contracts/EthereumDIDRegistry.json → bytecode
        // (the Truffle artifact whose networks map records the mainnet 0xdca7ef03… deployment)
        var bytecode = Erc1056Registry.LegacyCreationBytecode;

        bytecode.Length.Should().Be(8851);
        Convert.ToHexString(Keccak256.Hash(bytecode.Span)).ToLowerInvariant()
            .Should().Be("f5097e802068b423be9b9db53700d9444c5f7287a1176e77f282336722601e17");
    }

    [Fact]
    public void BothBytecodes_AreDistinctSolidityCreationCode()
    {
        // 0x6080604052 — the PUSH1 0x80 PUSH1 0x40 MSTORE prologue of both generations.
        Erc1056Registry.ModernCreationBytecode.Span[..5].ToArray()
            .Should().BeEquivalentTo(new byte[] { 0x60, 0x80, 0x60, 0x40, 0x52 });
        Erc1056Registry.LegacyCreationBytecode.Span[..5].ToArray()
            .Should().BeEquivalentTo(new byte[] { 0x60, 0x80, 0x60, 0x40, 0x52 });
        Erc1056Registry.ModernCreationBytecode.ToArray()
            .Should().NotBeEquivalentTo(Erc1056Registry.LegacyCreationBytecode.ToArray());
    }
}
