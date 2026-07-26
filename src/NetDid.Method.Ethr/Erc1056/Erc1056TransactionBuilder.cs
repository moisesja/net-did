using System.Numerics;
using System.Text;
using NetCrypto;
using NetDid.Method.Ethr.Abi;

namespace NetDid.Method.Ethr.Erc1056;

/// <summary>
/// One ERC-1056 registry mutation, carrying everything both submission paths need:
/// the direct calldata (controller pays gas), and — for the meta-transaction path —
/// the <c>abi.encodePacked</c> argument bytes of the <c>0x19 0x00</c> preimage plus a
/// factory for the corresponding <c>…Signed</c> calldata.
/// </summary>
internal sealed record Erc1056Operation
{
    /// <summary>The Solidity method name as it appears in the signed preimage (e.g. "changeOwner").</summary>
    public required string MethodName { get; init; }

    /// <summary>0x-prefixed calldata for the direct (msg.sender-authorized) call.</summary>
    public required string DirectCalldata { get; init; }

    /// <summary>The packed argument bytes appended after the method name in the meta-tx preimage.</summary>
    public required byte[] PackedArgs { get; init; }

    /// <summary>Builds the …Signed variant calldata from the controller's signature (v, r, s).</summary>
    public required Func<byte, byte[], byte[], string> SignedCalldata { get; init; }

    /// <summary>
    /// True for setAttribute / revokeAttribute: the legacy (v0.0.3) contract reads
    /// <c>nonce[identity]</c> for these preimages, while all other operations — and every
    /// operation on the modern contract — read <c>nonce[identityOwner(identity)]</c>.
    /// </summary>
    public required bool UsesIdentityNonceOnLegacy { get; init; }
}

/// <summary>
/// Builds ERC-1056 mutation calldata and meta-transaction preimages.
///
/// Selectors are keccak-computed at init; twelve of the thirteen registry selectors are
/// pinned against the 4byte.directory signature database in the test suite, certifying
/// the computation externally. Byte layouts follow the two verified contract sources
/// (uport-project/ethr-did-registry: modern 1.x pragma 0.8.6 and legacy v0.0.3 pragma
/// 0.4.4) — see the #107 plan notes.
/// </summary>
internal static class Erc1056TransactionBuilder
{
    // ── Selectors (external oracle: 4byte.directory, see Erc1056TransactionBuilderTests) ──

    private static readonly byte[] ChangeOwnerSelector           = Selector("changeOwner(address,address)");
    private static readonly byte[] ChangeOwnerSignedSelector     = Selector("changeOwnerSigned(address,uint8,bytes32,bytes32,address)");
    private static readonly byte[] AddDelegateSelector           = Selector("addDelegate(address,bytes32,address,uint256)");
    private static readonly byte[] AddDelegateSignedSelector     = Selector("addDelegateSigned(address,uint8,bytes32,bytes32,bytes32,address,uint256)");
    private static readonly byte[] RevokeDelegateSelector        = Selector("revokeDelegate(address,bytes32,address)");
    private static readonly byte[] RevokeDelegateSignedSelector  = Selector("revokeDelegateSigned(address,uint8,bytes32,bytes32,bytes32,address)");
    private static readonly byte[] SetAttributeSelector          = Selector("setAttribute(address,bytes32,bytes,uint256)");
    private static readonly byte[] SetAttributeSignedSelector    = Selector("setAttributeSigned(address,uint8,bytes32,bytes32,bytes32,bytes,uint256)");
    private static readonly byte[] RevokeAttributeSelector       = Selector("revokeAttribute(address,bytes32,bytes)");
    private static readonly byte[] RevokeAttributeSignedSelector = Selector("revokeAttributeSigned(address,uint8,bytes32,bytes32,bytes32,bytes)");
    private static readonly byte[] NonceSelector                 = Selector("nonce(address)");

    // ── Operations ────────────────────────────────────────────────────────────

    public static Erc1056Operation ChangeOwner(string identity, string newOwner)
    {
        var identityWord = AddressWord(identity, nameof(identity));
        var newOwnerBytes = ParseAddress(newOwner, nameof(newOwner));
        return new Erc1056Operation
        {
            MethodName     = "changeOwner",
            DirectCalldata = Calldata(ChangeOwnerSelector, identityWord, Word(newOwnerBytes)),
            PackedArgs     = newOwnerBytes,
            SignedCalldata = (v, r, s) => Calldata(
                ChangeOwnerSignedSelector, identityWord, U256(v), Exactly32(r), Exactly32(s),
                Word(newOwnerBytes)),
            UsesIdentityNonceOnLegacy = false,
        };
    }

    public static Erc1056Operation AddDelegate(
        string identity, string delegateType, string delegateAddress, ulong validitySeconds)
    {
        var identityWord = AddressWord(identity, nameof(identity));
        var typeWord     = Bytes32Label(delegateType, nameof(delegateType));
        var delegateBytes = ParseAddress(delegateAddress, nameof(delegateAddress));
        return new Erc1056Operation
        {
            MethodName     = "addDelegate",
            DirectCalldata = Calldata(
                AddDelegateSelector, identityWord, typeWord, Word(delegateBytes), U256(validitySeconds)),
            PackedArgs     = Concat(typeWord, delegateBytes, U256(validitySeconds)),
            SignedCalldata = (v, r, s) => Calldata(
                AddDelegateSignedSelector, identityWord, U256(v), Exactly32(r), Exactly32(s),
                typeWord, Word(delegateBytes), U256(validitySeconds)),
            UsesIdentityNonceOnLegacy = false,
        };
    }

    public static Erc1056Operation RevokeDelegate(
        string identity, string delegateType, string delegateAddress)
    {
        var identityWord = AddressWord(identity, nameof(identity));
        var typeWord     = Bytes32Label(delegateType, nameof(delegateType));
        var delegateBytes = ParseAddress(delegateAddress, nameof(delegateAddress));
        return new Erc1056Operation
        {
            MethodName     = "revokeDelegate",
            DirectCalldata = Calldata(
                RevokeDelegateSelector, identityWord, typeWord, Word(delegateBytes)),
            PackedArgs     = Concat(typeWord, delegateBytes),
            SignedCalldata = (v, r, s) => Calldata(
                RevokeDelegateSignedSelector, identityWord, U256(v), Exactly32(r), Exactly32(s),
                typeWord, Word(delegateBytes)),
            UsesIdentityNonceOnLegacy = false,
        };
    }

    public static Erc1056Operation SetAttribute(
        string identity, string name, byte[] value, ulong validitySeconds)
    {
        ArgumentNullException.ThrowIfNull(value);
        value = (byte[])value.Clone(); // snapshot: the caller's array must not mutate signed bytes
        var identityWord = AddressWord(identity, nameof(identity));
        var nameWord     = Bytes32Label(name, nameof(name));
        return new Erc1056Operation
        {
            MethodName     = "setAttribute",
            // setAttribute(address, bytes32, bytes, uint256): the dynamic `bytes` head slot
            // is arg 3 of 4 → tail begins at 4 · 32 = 0x80.
            DirectCalldata = Calldata(
                [identityWord, nameWord, U256(4 * 32), U256(validitySeconds)],
                DynamicBytesTail(value),
                SetAttributeSelector),
            PackedArgs     = Concat(nameWord, value, U256(validitySeconds)),
            // setAttributeSigned(address, uint8, bytes32, bytes32, bytes32, bytes, uint256):
            // head has 7 slots → tail begins at 7 · 32 = 0xe0.
            SignedCalldata = (v, r, s) => Calldata(
                [identityWord, U256(v), Exactly32(r), Exactly32(s), nameWord, U256(7 * 32), U256(validitySeconds)],
                DynamicBytesTail(value),
                SetAttributeSignedSelector),
            UsesIdentityNonceOnLegacy = true,
        };
    }

    public static Erc1056Operation RevokeAttribute(string identity, string name, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        value = (byte[])value.Clone(); // snapshot: the caller's array must not mutate signed bytes
        var identityWord = AddressWord(identity, nameof(identity));
        var nameWord     = Bytes32Label(name, nameof(name));
        return new Erc1056Operation
        {
            MethodName     = "revokeAttribute",
            // revokeAttribute(address, bytes32, bytes): head has 3 slots → tail at 0x60.
            DirectCalldata = Calldata(
                [identityWord, nameWord, U256(3 * 32)],
                DynamicBytesTail(value),
                RevokeAttributeSelector),
            PackedArgs     = Concat(nameWord, value),
            // revokeAttributeSigned(address, uint8, bytes32, bytes32, bytes32, bytes): 6 head slots → 0xc0.
            SignedCalldata = (v, r, s) => Calldata(
                [identityWord, U256(v), Exactly32(r), Exactly32(s), nameWord, U256(6 * 32)],
                DynamicBytesTail(value),
                RevokeAttributeSignedSelector),
            UsesIdentityNonceOnLegacy = true,
        };
    }

    /// <summary>0x-prefixed calldata for the public <c>nonce(address)</c> getter (meta-tx nonce fetch).</summary>
    public static string NonceCalldata(string address)
        => Calldata(NonceSelector, AddressWord(address, nameof(address)));

    // ── Meta-transaction preimage ─────────────────────────────────────────────

    /// <summary>
    /// The ERC-1056 meta-transaction signing digest:
    /// <c>keccak256(0x19 ‖ 0x00 ‖ registry ‖ nonce ‖ identity ‖ methodName ‖ packedArgs)</c>,
    /// per both verified contract generations (<c>abi.encodePacked</c> layout: addresses
    /// 20 bytes, uint256 32 bytes, bytes32 32 bytes, strings/bytes raw).
    /// </summary>
    public static byte[] MetaTransactionDigest(
        string registryAddress, BigInteger nonce, string identity, Erc1056Operation operation)
    {
        ArgumentNullException.ThrowIfNull(operation);
        var preimage = Concat(
            [0x19, 0x00],
            ParseAddress(registryAddress, nameof(registryAddress)),
            U256(nonce),
            ParseAddress(identity, nameof(identity)),
            Encoding.ASCII.GetBytes(operation.MethodName),
            operation.PackedArgs);
        return Keccak256.Hash(preimage);
    }

    // ── Encoding primitives ───────────────────────────────────────────────────

    private static byte[] Selector(string signature)
        => Keccak256.Hash(Encoding.ASCII.GetBytes(signature))[..4];

    private static string Calldata(byte[] selector, params byte[][] words)
        => Calldata(words, tail: [], selector);

    private static string Calldata(byte[][] headWords, byte[] tail, byte[] selector)
    {
        var result = new byte[4 + headWords.Sum(w => w.Length) + tail.Length];
        selector.CopyTo(result, 0);
        var offset = 4;
        foreach (var word in headWords)
        {
            word.CopyTo(result, offset);
            offset += word.Length;
        }
        tail.CopyTo(result, offset);
        return "0x" + Convert.ToHexString(result).ToLowerInvariant();
    }

    /// <summary>ABI dynamic-bytes tail: length word, then the value right-padded to a 32-byte multiple.</summary>
    private static byte[] DynamicBytesTail(byte[] value)
    {
        var paddedLength = (value.Length + 31) / 32 * 32;
        var tail = new byte[32 + paddedLength];
        U256((ulong)value.Length).CopyTo(tail, 0);
        value.CopyTo(tail, 32);
        return tail;
    }

    private static byte[] U256(ulong value) => U256((BigInteger)value);

    private static byte[] U256(BigInteger value)
    {
        if (value.Sign < 0)
            throw new ArgumentOutOfRangeException(nameof(value), value, "uint256 must be non-negative.");
        var minimal = value.IsZero ? [] : value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (minimal.Length > 32)
            throw new ArgumentOutOfRangeException(nameof(value), value, "Value exceeds uint256.");
        var word = new byte[32];
        minimal.CopyTo(word, 32 - minimal.Length);
        return word;
    }

    /// <summary>UTF-8 label right-padded into a bytes32 word (delegate types, attribute names).</summary>
    private static byte[] Bytes32Label(string label, string paramName)
    {
        ArgumentNullException.ThrowIfNull(label, paramName);
        var bytes = Encoding.UTF8.GetBytes(label);
        if (bytes.Length is 0 or > 32)
            throw new ArgumentException(
                $"'{label}' must encode to 1–32 UTF-8 bytes for a bytes32 field; got {bytes.Length}.",
                paramName);
        var word = new byte[32];
        bytes.CopyTo(word, 0);
        return word;
    }

    private static byte[] Exactly32(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length != 32)
            throw new ArgumentException($"Expected 32 bytes, got {value.Length}.", nameof(value));
        return value;
    }

    private static byte[] AddressWord(string address, string paramName)
        => Word(ParseAddress(address, paramName));

    private static byte[] Word(byte[] address20) => AbiEncoder.EncodeAddress(address20);

    private static byte[] ParseAddress(string address, string paramName)
    {
        ArgumentNullException.ThrowIfNull(address, paramName);
        var hex = address.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? address[2..] : address;
        byte[] bytes;
        try
        {
            bytes = Convert.FromHexString(hex);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException($"'{address}' is not valid hex.", paramName, ex);
        }
        if (bytes.Length != 20)
            throw new ArgumentException(
                $"Ethereum addresses are 20 bytes; got {bytes.Length}.", paramName);
        return bytes;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }
        return result;
    }
}
