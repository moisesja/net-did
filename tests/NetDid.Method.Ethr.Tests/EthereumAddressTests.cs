using acryptohashnet;
using FluentAssertions;
using NetDid.Core.Crypto;
using NetDid.Method.Ethr.Crypto;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Tests for Ethereum address derivation from public keys and EIP-55 checksum encoding.
/// Fixtures taken from the Ethereum Yellow Paper and EIP-55 specification.
/// </summary>
public class EthereumAddressTests
{
    // ── Keccak-256 correctness ───────────────────────────────────────────────

    [Fact]
    public void Keccak256_EmptyInput_MatchesEthereumYellowPaperVector()
    {
        // The Ethereum Yellow Paper / EIP-712 canonical empty-string Keccak-256.
        // This value differs from NIST SHA3-256 (different padding byte).
        var keccak = new Keccak256();
        var hash = keccak.ComputeHash([]);
        Convert.ToHexString(hash).ToLowerInvariant()
            .Should().Be("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    }

    // ── Address derivation ───────────────────────────────────────────────────

    /// <summary>
    /// Test vector from the Mastering Ethereum book (appendix A).
    /// Private key: f8f8a2f43c8376ccb0871305060d7b27b0554d2cc72bccf41b2705608452f315
    /// Public key y-coordinate ends in 0xd0 (even) → compressed prefix 0x02.
    /// Expected address: 0x001d3F1ef827552Ae1114027BD3ECF1f086bA0F9
    /// </summary>
    [Fact]
    public void FromCompressedPublicKey_MasteringEthereumVector_DerivesCorrectAddress()
    {
        var compressed = Convert.FromHexString(
            "026e145ccef1033dea239875dd00dfb4fee6e3348b84985c92f103444683bae07b");

        var address = EthereumAddress.FromCompressedPublicKey(compressed);

        address.ToLowerInvariant().Should().Be("0x001d3f1ef827552ae1114027bd3ecf1f086ba0f9");
    }

    [Fact]
    public void FromCompressedPublicKey_ProducesValidEip55ChecksumAddress()
    {
        // Use DefaultKeyGenerator with a known private key so the test is stable.
        var keyGen = new DefaultKeyGenerator();
        var privateKey = Convert.FromHexString(
            "4646464646464646464646464646464646464646464646464646464646464646");
        var keyPair = keyGen.FromPrivateKey(KeyType.Secp256k1, privateKey);

        var address = EthereumAddress.FromCompressedPublicKey(keyPair.PublicKey);

        // Structural checks
        address.Should().StartWith("0x");
        address.Should().HaveLength(42);
        // EIP-55: checksum is idempotent
        var addrBytes = Convert.FromHexString(address[2..]);
        EthereumAddress.ToChecksumAddress(addrBytes).Should().Be(address);
    }

    // ── EIP-55 checksum encoding ──────────────────────────────────────────────

    // Test vectors from the EIP-55 specification.
    private static readonly string[] Eip55Vectors =
    [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];

    [Theory]
    [MemberData(nameof(Eip55Vectors_Data))]
    public void ToChecksumAddress_Eip55Vectors_ProduceExpectedMixedCase(string expected)
    {
        var addrBytes = Convert.FromHexString(expected[2..]);
        EthereumAddress.ToChecksumAddress(addrBytes).Should().Be(expected);
    }

    public static IEnumerable<object[]> Eip55Vectors_Data()
        => Eip55Vectors.Select(v => new object[] { v });
}
