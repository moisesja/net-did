using System.Numerics;
using System.Text;
using FluentAssertions;
using NetCrypto;
using NetDid.Method.Ethr.Abi;
using NetDid.Method.Ethr.Erc1056;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// ERC-1056 write calldata and meta-transaction preimages (issue #107).
///
/// Selector expectations are an EXTERNAL oracle: the hex constants below were taken from
/// the 4byte.directory public signature database (and the two registry deployments are
/// verified contracts), so the keccak-based selector computation is certified against
/// published values, not against itself. Byte layouts follow the verified contract
/// sources; the Anvil integration suite proves them against the real bytecode.
/// </summary>
public class Erc1056TransactionBuilderTests
{
    private const string Identity  = "0xf61c81096c96f97e95ac52a570966195ad6c90dd";
    private const string NewOwner  = "0xa11ce00000000000000000000000000000000001";
    private const string Delegate  = "0xb0b0000000000000000000000000000000000002";
    private const string Registry  = "0x03d5003bf0e79c5f5223588f347eba39afbc3818";

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    // ── Selectors: external 4byte.directory constants ────────────────────────

    [Fact]
    public void DirectSelectors_MatchThePublicSignatureDatabase()
    {
        Erc1056TransactionBuilder.ChangeOwner(Identity, NewOwner)
            .DirectCalldata.Should().StartWith("0xf00d4b5d");
        Erc1056TransactionBuilder.AddDelegate(Identity, "sigAuth", Delegate, 86400)
            .DirectCalldata.Should().StartWith("0xa7068d66");
        Erc1056TransactionBuilder.RevokeDelegate(Identity, "sigAuth", Delegate)
            .DirectCalldata.Should().StartWith("0x80b29f7c");
        Erc1056TransactionBuilder.SetAttribute(Identity, "did/svc/Hub", [0x01], 86400)
            .DirectCalldata.Should().StartWith("0x7ad4b0a4");
        Erc1056TransactionBuilder.RevokeAttribute(Identity, "did/svc/Hub", [0x01])
            .DirectCalldata.Should().StartWith("0x00c023da");
    }

    [Fact]
    public void SignedSelectors_MatchThePublicSignatureDatabase()
    {
        var r = new byte[32];
        var s = new byte[32];
        Erc1056TransactionBuilder.ChangeOwner(Identity, NewOwner)
            .SignedCalldata(27, r, s).Should().StartWith("0x240cf1fa");
        Erc1056TransactionBuilder.AddDelegate(Identity, "sigAuth", Delegate, 86400)
            .SignedCalldata(27, r, s).Should().StartWith("0x9c2c1b2b");
        Erc1056TransactionBuilder.RevokeDelegate(Identity, "sigAuth", Delegate)
            .SignedCalldata(27, r, s).Should().StartWith("0x93072684");
        Erc1056TransactionBuilder.SetAttribute(Identity, "did/svc/Hub", [0x01], 86400)
            .SignedCalldata(27, r, s).Should().StartWith("0x123b5e98");
        Erc1056TransactionBuilder.RevokeAttribute(Identity, "did/svc/Hub", [0x01])
            .SignedCalldata(27, r, s).Should().StartWith("0xe476af5c");
    }

    [Fact]
    public void ReadSelectors_MatchThePublicSignatureDatabase()
    {
        // The two read selectors AbiEncoder computes at init, certified the same way.
        Hex(AbiEncoder.IdentityOwnerSelector).Should().Be("8733d4e8");
        Hex(AbiEncoder.ChangedSelector).Should().Be("f96d0f9f");
    }

    // ── Static argument layout ───────────────────────────────────────────────

    [Fact]
    public void ChangeOwner_DirectCalldata_IsSelectorPlusTwoAddressWords()
    {
        var calldata = Erc1056TransactionBuilder.ChangeOwner(Identity, NewOwner).DirectCalldata;

        calldata.Should().HaveLength(2 + (4 + 64) * 2); // 0x + hex(4-byte selector + 2 words)
        calldata[10..74].Should().Be("000000000000000000000000" + Identity[2..]);
        calldata[74..].Should().Be("000000000000000000000000" + NewOwner[2..]);
    }

    [Fact]
    public void AddDelegate_EncodesTypeValidityAndDelegate()
    {
        var calldata = Erc1056TransactionBuilder
            .AddDelegate(Identity, "veriKey", Delegate, validitySeconds: 3600).DirectCalldata;
        var words = Convert.FromHexString(calldata[10..]);

        words.Should().HaveCount(4 * 32);
        // bytes32 "veriKey" — UTF-8, right-padded with zeros.
        var typeWord = new byte[32];
        Encoding.UTF8.GetBytes("veriKey").CopyTo(typeWord, 0);
        words[32..64].Should().BeEquivalentTo(typeWord);
        // uint256 validity = 3600 = 0x0e10.
        new BigInteger(words[96..128], isUnsigned: true, isBigEndian: true)
            .Should().Be(3600);
    }

    // ── Dynamic bytes layout ─────────────────────────────────────────────────

    [Fact]
    public void SetAttribute_DynamicValue_UsesAbiOffsetLengthPadding()
    {
        var value = Encoding.UTF8.GetBytes("https://hub.example.com/messages"); // 32 bytes
        var calldata = Erc1056TransactionBuilder
            .SetAttribute(Identity, "did/svc/HubService", value, 999).DirectCalldata;
        var data = Convert.FromHexString(calldata[10..]);

        // Head: identity, name, offset (must point past the 4-slot head = 0x80), validity.
        new BigInteger(data[64..96], isUnsigned: true, isBigEndian: true).Should().Be(0x80);
        new BigInteger(data[96..128], isUnsigned: true, isBigEndian: true).Should().Be(999);

        // Decode the dynamic section back through AbiDecoder (independently vetted against
        // the ABI spec and hostile inputs) — offset word sits at byte 64 of the data.
        AbiDecoder.DecodeDynamicBytes(data, 64).Should().BeEquivalentTo(value);
    }

    [Fact]
    public void SetAttribute_NonMultipleLength_PadsTailTo32()
    {
        var value = new byte[5] { 1, 2, 3, 4, 5 };
        var calldata = Erc1056TransactionBuilder
            .SetAttribute(Identity, "did/pub/Ed25519/veriKey/base64", value, 1).DirectCalldata;
        var data = Convert.FromHexString(calldata[10..]);

        data.Should().HaveCount(4 * 32 + 32 + 32); // head + length word + one padded chunk
        AbiDecoder.DecodeDynamicBytes(data, 64).Should().BeEquivalentTo(value);
        data[^27..].Should().AllBeEquivalentTo((byte)0); // zero padding after the 5 bytes
    }

    [Fact]
    public void RevokeAttribute_OffsetPointsPastThreeSlotHead()
    {
        var value = new byte[40];
        var calldata = Erc1056TransactionBuilder
            .RevokeAttribute(Identity, "did/svc/Hub", value).DirectCalldata;
        var data = Convert.FromHexString(calldata[10..]);

        new BigInteger(data[64..96], isUnsigned: true, isBigEndian: true).Should().Be(0x60);
        AbiDecoder.DecodeDynamicBytes(data, 64).Should().BeEquivalentTo(value);
    }

    [Fact]
    public void SetAttributeSigned_OffsetPointsPastSevenSlotHead()
    {
        var value = new byte[33];
        var op = Erc1056TransactionBuilder.SetAttribute(Identity, "did/svc/Hub", value, 7);
        var data = Convert.FromHexString(op.SignedCalldata(28, new byte[32], new byte[32])[10..]);

        // Head: identity, sigV, sigR, sigS, name, offset, validity — offset at slot index 5.
        new BigInteger(data[(5 * 32)..(6 * 32)], isUnsigned: true, isBigEndian: true)
            .Should().Be(7 * 32);
        new BigInteger(data[(6 * 32)..(7 * 32)], isUnsigned: true, isBigEndian: true)
            .Should().Be(7);
        AbiDecoder.DecodeDynamicBytes(data, 5 * 32).Should().BeEquivalentTo(value);
    }

    // ── Meta-transaction preimage ────────────────────────────────────────────

    [Fact]
    public void MetaTransactionDigest_MatchesTheContractPreimageLayout()
    {
        // keccak256(0x19 ‖ 0x00 ‖ registry(20) ‖ nonce(32) ‖ identity(20) ‖ "changeOwner" ‖ newOwner(20))
        // — assembled here by hand from the verified contract source's abi.encodePacked call.
        var expectedPreimage = new List<byte> { 0x19, 0x00 };
        expectedPreimage.AddRange(Convert.FromHexString(Registry[2..]));
        var nonceWord = new byte[32];
        nonceWord[31] = 0x05;
        expectedPreimage.AddRange(nonceWord);
        expectedPreimage.AddRange(Convert.FromHexString(Identity[2..]));
        expectedPreimage.AddRange(Encoding.ASCII.GetBytes("changeOwner"));
        expectedPreimage.AddRange(Convert.FromHexString(NewOwner[2..]));

        var digest = Erc1056TransactionBuilder.MetaTransactionDigest(
            Registry, nonce: 5, Identity,
            Erc1056TransactionBuilder.ChangeOwner(Identity, NewOwner));

        digest.Should().BeEquivalentTo(Keccak256.Hash(expectedPreimage.ToArray()));
    }

    [Fact]
    public void MetaTransactionDigest_SetAttribute_PacksRawValueBytes()
    {
        // Attribute values are packed RAW (no length prefix, no padding) per abi.encodePacked.
        var value = Encoding.UTF8.GetBytes("https://example.com/hub");
        var expectedPreimage = new List<byte> { 0x19, 0x00 };
        expectedPreimage.AddRange(Convert.FromHexString(Registry[2..]));
        expectedPreimage.AddRange(new byte[32]); // nonce 0
        expectedPreimage.AddRange(Convert.FromHexString(Identity[2..]));
        expectedPreimage.AddRange(Encoding.ASCII.GetBytes("setAttribute"));
        var nameWord = new byte[32];
        Encoding.UTF8.GetBytes("did/svc/Hub").CopyTo(nameWord, 0);
        expectedPreimage.AddRange(nameWord);
        expectedPreimage.AddRange(value);
        var validityWord = new byte[32];
        validityWord[31] = 0x0a;
        expectedPreimage.AddRange(validityWord);

        var digest = Erc1056TransactionBuilder.MetaTransactionDigest(
            Registry, nonce: BigInteger.Zero, Identity,
            Erc1056TransactionBuilder.SetAttribute(Identity, "did/svc/Hub", value, 10));

        digest.Should().BeEquivalentTo(Keccak256.Hash(expectedPreimage.ToArray()));
    }

    [Fact]
    public void LegacyNonceKeyFlag_IsSetExactlyForAttributeOperations()
    {
        Erc1056TransactionBuilder.ChangeOwner(Identity, NewOwner)
            .UsesIdentityNonceOnLegacy.Should().BeFalse();
        Erc1056TransactionBuilder.AddDelegate(Identity, "sigAuth", Delegate, 1)
            .UsesIdentityNonceOnLegacy.Should().BeFalse();
        Erc1056TransactionBuilder.RevokeDelegate(Identity, "sigAuth", Delegate)
            .UsesIdentityNonceOnLegacy.Should().BeFalse();
        Erc1056TransactionBuilder.SetAttribute(Identity, "did/svc/Hub", [1], 1)
            .UsesIdentityNonceOnLegacy.Should().BeTrue();
        Erc1056TransactionBuilder.RevokeAttribute(Identity, "did/svc/Hub", [1])
            .UsesIdentityNonceOnLegacy.Should().BeTrue();
    }

    // ── Guards ───────────────────────────────────────────────────────────────

    [Fact]
    public void MalformedAddresses_ThrowParameterNamedArgumentException()
    {
        ((Action)(() => Erc1056TransactionBuilder.ChangeOwner("0xdeadbeef", NewOwner)))
            .Should().Throw<ArgumentException>().WithParameterName("identity");
        ((Action)(() => Erc1056TransactionBuilder.ChangeOwner(Identity, "not-hex")))
            .Should().Throw<ArgumentException>().WithParameterName("newOwner");
    }

    [Fact]
    public void Bytes32Labels_RejectEmptyAndOversized()
    {
        ((Action)(() => Erc1056TransactionBuilder.AddDelegate(Identity, "", Delegate, 1)))
            .Should().Throw<ArgumentException>().WithParameterName("delegateType");
        ((Action)(() => Erc1056TransactionBuilder.SetAttribute(
                Identity, new string('a', 33), [1], 1)))
            .Should().Throw<ArgumentException>().WithParameterName("name");
    }

    [Fact]
    public void SignedCalldata_RejectsWrongSignatureComponentLengths()
    {
        var op = Erc1056TransactionBuilder.ChangeOwner(Identity, NewOwner);
        ((Action)(() => op.SignedCalldata(27, new byte[31], new byte[32])))
            .Should().Throw<ArgumentException>();
        ((Action)(() => op.SignedCalldata(27, new byte[32], new byte[33])))
            .Should().Throw<ArgumentException>();
    }

    [Fact]
    public void NonceCalldata_IsSelectorPlusAddressWord()
    {
        var calldata = Erc1056TransactionBuilder.NonceCalldata(Identity);
        calldata.Should().HaveLength(2 + (4 + 32) * 2);
        calldata[10..].Should().Be("000000000000000000000000" + Identity[2..]);
    }
}
