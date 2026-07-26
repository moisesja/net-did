using System.Numerics;
using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Transactions;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// EIP-155 transaction construction, pinned byte-for-byte against the canonical example
/// PUBLISHED IN EIP-155 ITSELF (an external oracle, not this repo's own encoder):
///
///   nonce 9, gasPrice 20·10⁹, gas 21000, to 0x3535…35, value 10¹⁸, data ∅, chain id 1,
///   private key 0x4646…46 →
///     signing payload 0xec098504a817c800825208…018080
///     signing hash    0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53
///     v 37, r 0x28ef6134…6276, s 0x67cbe9d8…6d83
/// </summary>
public class EthereumTransactionTests
{
    private static readonly byte[] Eip155PrivateKey =
        Convert.FromHexString("4646464646464646464646464646464646464646464646464646464646464646");

    private static EthereumTransaction Eip155Example => new()
    {
        Nonce    = 9,
        GasPrice = 20_000_000_000,
        GasLimit = 21_000,
        To       = "0x3535353535353535353535353535353535353535",
        Value    = BigInteger.Pow(10, 18),
        Data     = [],
        ChainId  = 1,
    };

    private const string ExpectedSigningPayload =
        "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";

    private const string ExpectedSigningHash =
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";

    private const string ExpectedR = "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276";
    private const string ExpectedS = "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

    private const string ExpectedSignedRaw =
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000" +
        "8025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f" +
        "761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    [Fact]
    public void SigningPayload_MatchesEip155PublishedBytes()
        => Hex(Eip155Example.SigningPayload()).Should().Be(ExpectedSigningPayload);

    [Fact]
    public void SigningDigest_MatchesEip155PublishedHash()
        => Hex(Eip155Example.SigningDigest()).Should().Be(ExpectedSigningHash);

    [Fact]
    public void Sign_WithNetCrypto_ReproducesEip155PublishedSignature()
    {
        // RFC 6979 is deterministic, so NetCrypto must land on the EXACT published r/s.
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(
            Eip155PrivateKey, Eip155Example.SigningDigest());

        Hex(signature[..32]).Should().Be(ExpectedR);
        Hex(signature[32..]).Should().Be(ExpectedS);
        recoveryId.Should().Be(0); // published v = 37 = 35 + 2·1 + 0
    }

    [Fact]
    public void EncodeSigned_MatchesEip155PublishedRawTransaction()
    {
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(
            Eip155PrivateKey, Eip155Example.SigningDigest());

        Hex(Eip155Example.EncodeSigned(signature, recoveryId)).Should().Be(ExpectedSignedRaw);
    }

    [Fact]
    public void RecoveredSender_MatchesTheExampleKeysAddress()
    {
        var digest = Eip155Example.SigningDigest();
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(Eip155PrivateKey, digest);

        var compressed = Secp256k1Recoverable.RecoverPublicKey(
            digest, signature, recoveryId, compressed: true);
        var sender = EthereumAddress.FromCompressedPublicKey(compressed);

        // Address of the EIP-155 example key 0x4646…46 (derivable with any Ethereum wallet tool).
        sender.ToLowerInvariant().Should().Be("0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f");
    }

    // ── Structure and guards ─────────────────────────────────────────────────

    [Fact]
    public void ContractCreation_EncodesEmptyRecipient()
    {
        var creation = Eip155Example with { To = null, Data = [0x60, 0x80] };
        // No published vector for this shape; structural checks only — the Anvil
        // integration suite proves creation transactions against a real node.
        var payload = creation.SigningPayload();
        payload.Should().NotBeEmpty();
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(
            Eip155PrivateKey, creation.SigningDigest());
        var act = () => creation.EncodeSigned(signature, recoveryId);
        act.Should().NotThrow();
    }

    [Fact]
    public void EncodeSigned_WrongSignatureLength_Throws()
    {
        var act = () => Eip155Example.EncodeSigned(new byte[63], 0);
        act.Should().Throw<ArgumentException>().WithParameterName("signature64");
    }

    [Fact]
    public void EncodeSigned_NonCanonicalScalars_Throw()
    {
        // The signature arrives through the caller-supplied signer seam, so validate it here
        // rather than discovering it from a node rejection.
        ((Action)(() => Eip155Example.EncodeSigned(new byte[64], 0)))
            .Should().Throw<ArgumentException>().WithMessage("*canonical values*");

        var order = Convert.FromHexString(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        var atOrder = new byte[64];
        order.CopyTo(atOrder, 0);
        order.CopyTo(atOrder, 32);
        ((Action)(() => Eip155Example.EncodeSigned(atOrder, 0)))
            .Should().Throw<ArgumentException>().WithMessage("*canonical values*");
    }

    [Fact]
    public void EncodeSigned_HighS_IsRejected()
    {
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(
            Eip155PrivateKey, Eip155Example.SigningDigest());
        var order = new BigInteger(
            Convert.FromHexString("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(signature[32..], isUnsigned: true, isBigEndian: true);
        var malleated = new byte[64];
        signature[..32].CopyTo(malleated, 0);
        var highS = (order - s).ToByteArray(isUnsigned: true, isBigEndian: true);
        highS.CopyTo(malleated, 64 - highS.Length);

        ((Action)(() => Eip155Example.EncodeSigned(malleated, recoveryId ^ 1)))
            .Should().Throw<ArgumentException>().WithMessage("*low-S*");
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    public void EncodeSigned_RecoveryIdOutsideEvmRange_Throws(int recoveryId)
    {
        var act = () => Eip155Example.EncodeSigned(new byte[64], recoveryId);
        act.Should().Throw<ArgumentOutOfRangeException>().WithParameterName("recoveryId");
    }

    [Fact]
    public void MalformedRecipient_Throws()
    {
        var badLength = Eip155Example with { To = "0xdeadbeef" };
        ((Action)(() => badLength.SigningPayload()))
            .Should().Throw<ArgumentException>().WithParameterName("address");

        var badHex = Eip155Example with { To = "0x35353535353535353535353535353535353535zz" };
        ((Action)(() => badHex.SigningPayload()))
            .Should().Throw<ArgumentException>().WithParameterName("address");
    }

    [Fact]
    public void NegativeAmounts_Throw()
    {
        var negativeValue = Eip155Example with { Value = BigInteger.MinusOne };
        ((Action)(() => negativeValue.SigningPayload()))
            .Should().Throw<ArgumentOutOfRangeException>().WithParameterName("Value");

        var negativeGasPrice = Eip155Example with { GasPrice = BigInteger.MinusOne };
        ((Action)(() => negativeGasPrice.SigningPayload()))
            .Should().Throw<ArgumentOutOfRangeException>().WithParameterName("GasPrice");
    }

    [Fact]
    public void HashOf_IsKeccakOfRawBytes()
    {
        var (signature, recoveryId) = Secp256k1Recoverable.Sign(
            Eip155PrivateKey, Eip155Example.SigningDigest());
        var raw = Eip155Example.EncodeSigned(signature, recoveryId);

        var hash = EthereumTransaction.HashOf(raw);

        hash.Should().StartWith("0x").And.HaveLength(66);
        hash.Should().Be("0x" + Hex(Keccak256.Hash(raw)));
    }
}
