using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using NetCrypto;
using NetDid.Method.Ethr.Crypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr.Emulator;

/// <summary>
/// An in-memory Ethereum node hosting ERC-1056 registries — the "mock blockchain" for
/// unit tests and samples. It is honest at the protocol boundary:
///
///   • <c>eth_sendRawTransaction</c> RLP-decodes the raw bytes with a strict independent
///     decoder, recomputes the EIP-155 signing digest, recovers the sender with REAL
///     ecrecover (<see cref="Secp256k1Recoverable"/>), and enforces chain id, account
///     nonce, low-S, and canonical scalars — no test back-doors: authorization comes from
///     signature recovery, exactly like a real node.
///   • Registry semantics are transcribed from the two VERIFIED contract sources
///     (uport-project/ethr-did-registry — modern 1.x and legacy v0.0.3), including the
///     meta-transaction <c>0x19 0x00</c> preimage check and the generation-specific
///     nonce bookkeeping (the constructor's <c>legacyNonce</c> flag).
///   • A reverted registry call still mines a block and consumes the account nonce,
///     producing a <c>status: 0x0</c> receipt — like the EVM, not like an RPC error.
///
/// It cannot execute EVM bytecode: contract-creation transactions succeed only for
/// creation bytecode registered via <see cref="RecognizeDeployableRegistry"/> (the
/// vendored registry artifacts), with the real <c>CREATE</c> address derivation.
/// The Anvil integration suite remains the true EVM oracle.
/// </summary>
public sealed class EmulatedEthereumChain : IEthereumRpcClient
{
    private static readonly BigInteger CurveOrder = BigInteger.Parse(
        "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        NumberStyles.HexNumber);
    private static readonly BigInteger HalfCurveOrder = CurveOrder / 2;

    private const ulong BlockIntervalSeconds = 12;
    private const string ZeroAddress = "0x0000000000000000000000000000000000000000";

    private sealed class RegistryInstance
    {
        public required bool LegacyNonce { get; init; }
        public Dictionary<string, string> Owners { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, BigInteger> MetaNonces { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, ulong> Changed { get; } = new(StringComparer.Ordinal);

        public string IdentityOwner(string identity)
            => Owners.TryGetValue(identity, out var owner) ? owner : identity;

        public BigInteger MetaNonce(string account)
            => MetaNonces.TryGetValue(account, out var nonce) ? nonce : BigInteger.Zero;
    }

    private sealed record Block(ulong Number, ulong Timestamp, List<EthereumLogEntry> Logs);

    private readonly Dictionary<string, RegistryInstance> _registries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, bool> _deployableRegistries = new(StringComparer.Ordinal); // keccak(bytecode) → legacyNonce
    private readonly Dictionary<string, ulong> _accountNonces = new(StringComparer.Ordinal);
    private readonly Dictionary<string, BigInteger> _balances = new(StringComparer.Ordinal);
    private readonly Dictionary<string, EthereumTransactionReceipt> _receipts = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Block> _blocks = [];
    private readonly ulong _chainId;
    private ulong _extraTimeSkew;

    public EmulatedEthereumChain(
        string registryAddress,
        ulong chainId = 11155111,
        bool legacyNonce = false,
        DateTimeOffset? genesisTime = null)
    {
        ArgumentNullException.ThrowIfNull(registryAddress);
        _chainId = chainId;
        // Default the genesis clock near wall-clock so validTo values computed against
        // "now" behave the same way for the emulator and the UtcNow-based resolver.
        var genesis = (ulong)(genesisTime ?? DateTimeOffset.UtcNow.AddHours(-1)).ToUnixTimeSeconds();
        _blocks.Add(new Block(0, genesis, []));
        _registries[Normalize(registryAddress)] = new RegistryInstance { LegacyNonce = legacyNonce };
    }

    // ── Test/sample helpers ──────────────────────────────────────────────────

    public ulong CurrentBlockNumber => _blocks[^1].Number;

    public ulong CurrentTimestamp => _blocks[^1].Timestamp;

    /// <summary>Seed an account balance (the chain is gas-free; balances gate only transferred value).</summary>
    public void FundAccount(string address, BigInteger wei)
        => _balances[Normalize(address)] = wei;

    public BigInteger BalanceOf(string address)
        => _balances.TryGetValue(Normalize(address), out var balance) ? balance : BigInteger.Zero;

    /// <summary>Advance the chain clock so future blocks are minted after the given delay (expiry demos).</summary>
    public void AdvanceTime(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(delta), delta, "Time can only advance.");
        _extraTimeSkew += (ulong)delta.TotalSeconds;
    }

    /// <summary>
    /// Registers a contract-creation bytecode (keyed by its keccak256) that this chain
    /// recognizes as an ERC-1056 registry deployment.
    /// </summary>
    public void RecognizeDeployableRegistry(byte[] creationBytecode, bool legacyNonce)
    {
        ArgumentNullException.ThrowIfNull(creationBytecode);
        _deployableRegistries[Convert.ToHexString(Keccak256.Hash(creationBytecode))] = legacyNonce;
    }

    // ── IEthereumRpcClient: reads ────────────────────────────────────────────

    public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
    {
        var registry = _registries.TryGetValue(Normalize(to), out var instance)
            ? instance
            : throw new EthereumInteractionException($"eth_call to unknown contract '{to}'.");

        var calldata = FromHex(data);
        if (calldata.Length < 4 + 32)
            throw new EthereumInteractionException("eth_call calldata is too short.");
        var selector = Convert.ToHexString(calldata[..4]).ToLowerInvariant();
        var argAddress = AddressFromWord(calldata.AsSpan(4, 32));

        var word = selector switch
        {
            "f96d0f9f" => U256Word(registry.Changed.GetValueOrDefault(argAddress)),          // changed(address)
            "8733d4e8" => AddressWord(registry.IdentityOwner(argAddress)),                   // identityOwner(address)
            "70ae92d2" => U256Word(registry.MetaNonce(argAddress)),                          // nonce(address)
            _ => throw new EthereumInteractionException($"eth_call selector 0x{selector} is not supported."),
        };
        return Task.FromResult("0x" + Convert.ToHexString(word).ToLowerInvariant());
    }

    public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(
        EthereumLogFilter filter, CancellationToken ct = default)
    {
        var matches = new List<EthereumLogEntry>();
        foreach (var block in _blocks)
        {
            if (block.Number < filter.FromBlock || block.Number > filter.ToBlock)
                continue;
            foreach (var log in block.Logs)
            {
                if (!string.Equals(log.Address, filter.Address, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!TopicsMatch(filter.Topics, log.Topics))
                    continue;
                matches.Add(log);
            }
        }
        return Task.FromResult<IReadOnlyList<EthereumLogEntry>>(matches);
    }

    public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default)
        => Task.FromResult(CurrentBlockNumber);

    public Task<ulong> GetChainIdAsync(CancellationToken ct = default)
        => Task.FromResult(_chainId);

    public Task<ulong> GetBlockTimestampAsync(ulong blockNumber, CancellationToken ct = default)
        => blockNumber < (ulong)_blocks.Count
            ? Task.FromResult(_blocks[(int)blockNumber].Timestamp)
            : throw new EthereumInteractionException($"Block {blockNumber} does not exist.");

    // ── IEthereumRpcClient: writes ───────────────────────────────────────────

    public Task<string> SendRawTransactionAsync(byte[] signedTransaction, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(signedTransaction);

        ParsedTransaction tx;
        try
        {
            tx = ParseSignedTransaction(signedTransaction);
        }
        catch (FormatException ex)
        {
            throw new EthereumInteractionException($"Invalid raw transaction: {ex.Message}", ex);
        }

        // EIP-155 v → recovery id + chain id binding.
        if (tx.V < 35)
            throw new EthereumInteractionException(
                "Only EIP-155 replay-protected transactions are accepted (v ≥ 35).");
        var recoveryId = (int)((tx.V - 35) % 2);
        var chainId = (tx.V - 35 - recoveryId) / 2;
        if (chainId != _chainId)
            throw new EthereumInteractionException(
                $"Transaction is signed for chain {chainId}, this chain is {_chainId}.");

        // Canonical scalars; EIP-2 low-S.
        if (tx.R.IsZero || tx.S.IsZero || tx.R >= CurveOrder || tx.S >= CurveOrder)
            throw new EthereumInteractionException("Transaction signature scalars are out of range.");
        if (tx.S > HalfCurveOrder)
            throw new EthereumInteractionException("Transaction signature must be low-S (EIP-2).");

        // Recompute the signing digest and recover the sender — real ecrecover.
        var signingDigest = Keccak256.Hash(EncodeSigningPayload(tx));
        string sender;
        try
        {
            var compressed = Secp256k1Recoverable.RecoverPublicKey(
                signingDigest, Concat(ScalarBytes(tx.R), ScalarBytes(tx.S)), recoveryId, compressed: true);
            sender = Normalize(EthereumAddress.FromCompressedPublicKey(compressed));
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new EthereumInteractionException("Transaction signature does not recover a sender.", ex);
        }

        var expectedNonce = _accountNonces.GetValueOrDefault(sender);
        if (tx.Nonce != expectedNonce)
            throw new EthereumInteractionException(
                $"Nonce {tx.Nonce} does not match account nonce {expectedNonce} for {sender}.");

        if (tx.Value.Sign > 0 && BalanceOf(sender) < tx.Value)
            throw new EthereumInteractionException($"Insufficient funds: {sender} cannot transfer {tx.Value} wei.");

        // ── Execute: every accepted transaction mines one block and consumes the nonce.
        var blockNumber = CurrentBlockNumber + 1;
        var timestamp = _blocks[^1].Timestamp + BlockIntervalSeconds + _extraTimeSkew;
        _extraTimeSkew = 0;
        var logs = new List<EthereumLogEntry>();
        var succeeded = true;
        string? contractAddress = null;

        if (tx.To is null)
        {
            contractAddress = DeriveCreateAddress(sender, tx.Nonce);
            var bytecodeHash = Convert.ToHexString(Keccak256.Hash(tx.Data));
            if (_deployableRegistries.TryGetValue(bytecodeHash, out var legacyNonce))
                _registries[contractAddress] = new RegistryInstance { LegacyNonce = legacyNonce };
            else
                succeeded = false; // unrecognized bytecode: the emulator cannot run an EVM
        }
        else if (_registries.TryGetValue(tx.To, out var registry))
        {
            succeeded = TryExecuteRegistryCall(registry, tx.To, sender, tx.Data, blockNumber, timestamp, logs);
        }
        else
        {
            // Plain value transfer.
            if (tx.Value.Sign > 0)
            {
                _balances[sender] = BalanceOf(sender) - tx.Value;
                _balances[tx.To] = BalanceOf(tx.To) + tx.Value;
            }
        }

        _blocks.Add(new Block(blockNumber, timestamp, succeeded ? logs : []));
        _accountNonces[sender] = expectedNonce + 1;

        var txHash = "0x" + Convert.ToHexString(Keccak256.Hash(signedTransaction)).ToLowerInvariant();
        _receipts[txHash] = new EthereumTransactionReceipt
        {
            TransactionHash = txHash,
            BlockNumber     = blockNumber,
            Succeeded       = succeeded,
            ContractAddress = succeeded ? contractAddress : null,
        };
        return Task.FromResult(txHash);
    }

    public Task<ulong> GetTransactionCountAsync(string address, CancellationToken ct = default)
        => Task.FromResult(_accountNonces.GetValueOrDefault(Normalize(address)));

    public Task<ulong> GetGasPriceAsync(CancellationToken ct = default)
        => Task.FromResult(1_000_000_000UL); // 1 gwei

    public Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(
        string transactionHash, CancellationToken ct = default)
        => Task.FromResult(_receipts.GetValueOrDefault(transactionHash));

    public Task<ulong> EstimateGasAsync(string from, string? to, string data, CancellationToken ct = default)
        => Task.FromResult(data is "0x" or "" && to is not null ? 21_000UL : 100_000UL);

    // ── ERC-1056 semantics (transcribed from the verified contract sources) ──

    private bool TryExecuteRegistryCall(
        RegistryInstance registry, string registryAddress, string sender, byte[] calldata,
        ulong blockNumber, ulong timestamp, List<EthereumLogEntry> logs)
    {
        try
        {
            ExecuteRegistryCall(registry, registryAddress, sender, calldata, blockNumber, timestamp, logs);
            return true;
        }
        catch (RegistryRevertException)
        {
            return false;
        }
    }

    private sealed class RegistryRevertException(string reason) : Exception(reason);

    private void ExecuteRegistryCall(
        RegistryInstance registry, string registryAddress, string sender, byte[] calldata,
        ulong blockNumber, ulong timestamp, List<EthereumLogEntry> logs)
    {
        if (calldata.Length < 4)
            throw new RegistryRevertException("calldata too short");
        var selector = Convert.ToHexString(calldata[..4]).ToLowerInvariant();
        var args = new AbiArgs(calldata.AsSpan(4).ToArray());

        switch (selector)
        {
            case "f00d4b5d": // changeOwner(address identity, address newOwner)
            {
                var identity = args.Address(0);
                var newOwner = args.Address(1);
                ChangeOwner(registry, registryAddress, identity, sender, newOwner, blockNumber, logs);
                break;
            }
            case "240cf1fa": // changeOwnerSigned(address, uint8, bytes32, bytes32, address)
            {
                var identity = args.Address(0);
                var newOwner = args.Address(4);
                var signer = CheckSignature(registry, registryAddress, identity, args,
                    isAttributeOp: false, "changeOwner", FromHexAddress(newOwner));
                ChangeOwner(registry, registryAddress, identity, signer, newOwner, blockNumber, logs);
                break;
            }
            case "a7068d66": // addDelegate(address, bytes32, address, uint256)
            {
                var identity = args.Address(0);
                AddDelegate(registry, registryAddress, identity, sender,
                    args.Word(1), args.Address(2), args.U256(3), blockNumber, timestamp, logs);
                break;
            }
            case "9c2c1b2b": // addDelegateSigned(address, uint8, bytes32, bytes32, bytes32, address, uint256)
            {
                var identity = args.Address(0);
                var delegateType = args.Word(4);
                var delegateAddress = args.Address(5);
                var validity = args.U256(6);
                var signer = CheckSignature(registry, registryAddress, identity, args,
                    isAttributeOp: false, "addDelegate",
                    Concat(delegateType, FromHexAddress(delegateAddress), U256Word(validity)));
                AddDelegate(registry, registryAddress, identity, signer,
                    delegateType, delegateAddress, validity, blockNumber, timestamp, logs);
                break;
            }
            case "80b29f7c": // revokeDelegate(address, bytes32, address)
            {
                var identity = args.Address(0);
                RevokeDelegate(registry, registryAddress, identity, sender,
                    args.Word(1), args.Address(2), blockNumber, timestamp, logs);
                break;
            }
            case "93072684": // revokeDelegateSigned(address, uint8, bytes32, bytes32, bytes32, address)
            {
                var identity = args.Address(0);
                var delegateType = args.Word(4);
                var delegateAddress = args.Address(5);
                var signer = CheckSignature(registry, registryAddress, identity, args,
                    isAttributeOp: false, "revokeDelegate",
                    Concat(delegateType, FromHexAddress(delegateAddress)));
                RevokeDelegate(registry, registryAddress, identity, signer,
                    delegateType, delegateAddress, blockNumber, timestamp, logs);
                break;
            }
            case "7ad4b0a4": // setAttribute(address, bytes32, bytes, uint256)
            {
                var identity = args.Address(0);
                SetAttribute(registry, registryAddress, identity, sender,
                    args.Word(1), args.DynamicBytes(2), args.U256(3), blockNumber, timestamp, logs);
                break;
            }
            case "123b5e98": // setAttributeSigned(address, uint8, bytes32, bytes32, bytes32, bytes, uint256)
            {
                var identity = args.Address(0);
                var name = args.Word(4);
                var value = args.DynamicBytes(5);
                var validity = args.U256(6);
                var signer = CheckSignature(registry, registryAddress, identity, args,
                    isAttributeOp: true, "setAttribute",
                    Concat(name, value, U256Word(validity)));
                SetAttribute(registry, registryAddress, identity, signer,
                    name, value, validity, blockNumber, timestamp, logs);
                break;
            }
            case "00c023da": // revokeAttribute(address, bytes32, bytes)
            {
                var identity = args.Address(0);
                RevokeAttribute(registry, registryAddress, identity, sender,
                    args.Word(1), args.DynamicBytes(2), blockNumber, logs);
                break;
            }
            case "e476af5c": // revokeAttributeSigned(address, uint8, bytes32, bytes32, bytes32, bytes)
            {
                var identity = args.Address(0);
                var name = args.Word(4);
                var value = args.DynamicBytes(5);
                var signer = CheckSignature(registry, registryAddress, identity, args,
                    isAttributeOp: true, "revokeAttribute", Concat(name, value));
                RevokeAttribute(registry, registryAddress, identity, signer,
                    name, value, blockNumber, logs);
                break;
            }
            default:
                throw new RegistryRevertException($"unknown selector 0x{selector}");
        }
    }

    /// <summary>
    /// The contract's checkSignature: reconstruct the 0x19 0x00 preimage with the
    /// generation-appropriate nonce key, ecrecover, require the signer to be the identity
    /// owner, and consume the generation-appropriate nonce. Signature args live in
    /// calldata slots 1..3 (sigV, sigR, sigS).
    /// </summary>
    private string CheckSignature(
        RegistryInstance registry, string registryAddress, string identity, AbiArgs args,
        bool isAttributeOp, string methodName, byte[] packedArgs)
    {
        var sigV = args.U256(1);
        if (sigV != 27 && sigV != 28)
            throw new RegistryRevertException("bad_signature (sigV must be 27 or 28)");
        var sigR = args.Word(2);
        var sigS = args.Word(3);

        // Legacy (v0.0.3): attribute preimages read nonce[identity]; owner/delegate
        // preimages read nonce[identityOwner(identity)]. Modern (1.x): always the owner.
        var nonceKey = registry.LegacyNonce && isAttributeOp
            ? identity
            : registry.IdentityOwner(identity);

        var preimage = Concat(
            [0x19, 0x00],
            FromHexAddress(registryAddress),
            U256Word(registry.MetaNonce(nonceKey)),
            FromHexAddress(identity),
            Encoding.ASCII.GetBytes(methodName),
            packedArgs);
        var digest = Keccak256.Hash(preimage);

        string signer;
        try
        {
            var compressed = Secp256k1Recoverable.RecoverPublicKey(
                digest, Concat(sigR, sigS), (int)(sigV - 27), compressed: true);
            signer = Normalize(EthereumAddress.FromCompressedPublicKey(compressed));
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new RegistryRevertException($"bad_signature ({ex.Message})");
        }

        if (!string.Equals(signer, registry.IdentityOwner(identity), StringComparison.Ordinal))
            throw new RegistryRevertException("bad_signature (signer is not the identity owner)");

        // Legacy: nonce[identity]++. Modern: nonce[signer]++.
        var incrementKey = registry.LegacyNonce ? identity : signer;
        registry.MetaNonces[incrementKey] = registry.MetaNonce(incrementKey) + 1;
        return signer;
    }

    private static void RequireOwner(RegistryInstance registry, string identity, string actor)
    {
        if (!string.Equals(actor, registry.IdentityOwner(identity), StringComparison.Ordinal))
            throw new RegistryRevertException("bad_actor");
    }

    private void ChangeOwner(
        RegistryInstance registry, string registryAddress, string identity, string actor,
        string newOwner, ulong blockNumber, List<EthereumLogEntry> logs)
    {
        RequireOwner(registry, identity, actor);
        registry.Owners[identity] = newOwner;
        logs.Add(Log(registryAddress, Erc1056.Erc1056Topics.DIDOwnerChanged, identity, blockNumber,
            Concat(AddressWord(newOwner), U256Word(registry.Changed.GetValueOrDefault(identity)))));
        registry.Changed[identity] = blockNumber;
    }

    private void AddDelegate(
        RegistryInstance registry, string registryAddress, string identity, string actor,
        byte[] delegateType, string delegateAddress, BigInteger validity,
        ulong blockNumber, ulong timestamp, List<EthereumLogEntry> logs)
    {
        RequireOwner(registry, identity, actor);
        var validTo = timestamp + (ulong)validity;
        logs.Add(Log(registryAddress, Erc1056.Erc1056Topics.DIDDelegateChanged, identity, blockNumber,
            Concat(delegateType, AddressWord(delegateAddress), U256Word(validTo),
                   U256Word(registry.Changed.GetValueOrDefault(identity)))));
        registry.Changed[identity] = blockNumber;
    }

    private void RevokeDelegate(
        RegistryInstance registry, string registryAddress, string identity, string actor,
        byte[] delegateType, string delegateAddress,
        ulong blockNumber, ulong timestamp, List<EthereumLogEntry> logs)
    {
        RequireOwner(registry, identity, actor);
        logs.Add(Log(registryAddress, Erc1056.Erc1056Topics.DIDDelegateChanged, identity, blockNumber,
            Concat(delegateType, AddressWord(delegateAddress), U256Word(timestamp),
                   U256Word(registry.Changed.GetValueOrDefault(identity)))));
        registry.Changed[identity] = blockNumber;
    }

    private void SetAttribute(
        RegistryInstance registry, string registryAddress, string identity, string actor,
        byte[] name, byte[] value, BigInteger validity,
        ulong blockNumber, ulong timestamp, List<EthereumLogEntry> logs)
    {
        RequireOwner(registry, identity, actor);
        logs.Add(Log(registryAddress, Erc1056.Erc1056Topics.DIDAttributeChanged, identity, blockNumber,
            AttributeEventData(name, value, timestamp + (ulong)validity,
                registry.Changed.GetValueOrDefault(identity))));
        registry.Changed[identity] = blockNumber;
    }

    private void RevokeAttribute(
        RegistryInstance registry, string registryAddress, string identity, string actor,
        byte[] name, byte[] value, ulong blockNumber, List<EthereumLogEntry> logs)
    {
        RequireOwner(registry, identity, actor);
        logs.Add(Log(registryAddress, Erc1056.Erc1056Topics.DIDAttributeChanged, identity, blockNumber,
            AttributeEventData(name, value, validTo: 0, registry.Changed.GetValueOrDefault(identity))));
        registry.Changed[identity] = blockNumber;
    }

    // ── Event encoding (mirrors the contract ABI; consumed by Erc1056EventParser) ──

    private EthereumLogEntry Log(
        string registryAddress, string topic0, string identity, ulong blockNumber, byte[] data)
    {
        var block = blockNumber;
        var logIndexInBlock = 0UL; // one transaction per block ⇒ one registry event per block
        return new EthereumLogEntry
        {
            Address     = registryAddress,
            Topics      = [topic0, "0x" + Convert.ToHexString(AddressWord(identity)).ToLowerInvariant()],
            Data        = "0x" + Convert.ToHexString(data).ToLowerInvariant(),
            BlockNumber = "0x" + block.ToString("x"),
            LogIndex    = logIndexInBlock,
        };
    }

    /// <summary>DIDAttributeChanged data: name(32) ‖ offset(0x80) ‖ validTo(32) ‖ previousChange(32) ‖ length ‖ padded value.</summary>
    private static byte[] AttributeEventData(byte[] name, byte[] value, ulong validTo, ulong previousChange)
    {
        var paddedLength = (value.Length + 31) / 32 * 32;
        var tail = new byte[32 + paddedLength];
        U256Word((ulong)value.Length).CopyTo(tail, 0);
        value.CopyTo(tail, 32);
        return Concat(name, U256Word(0x80), U256Word(validTo), U256Word(previousChange), tail);
    }

    // ── Raw transaction parsing ──────────────────────────────────────────────

    private sealed record ParsedTransaction(
        ulong Nonce, BigInteger GasPrice, ulong GasLimit, string? To,
        BigInteger Value, byte[] Data, BigInteger V, BigInteger R, BigInteger S);

    private static ParsedTransaction ParseSignedTransaction(byte[] raw)
    {
        var top = RlpDecoder.Decode(raw);
        var items = top.AsList();
        if (items.Count != 9)
            throw new FormatException($"A legacy transaction has 9 fields, found {items.Count}.");

        var nonce = CanonicalUlong(items[0].AsBytes(), "nonce");
        var gasPrice = CanonicalUnsigned(items[1].AsBytes(), "gasPrice");
        var gasLimit = CanonicalUlong(items[2].AsBytes(), "gasLimit");
        var toBytes = items[3].AsBytes();
        var to = toBytes.Length switch
        {
            0 => (string?)null,
            20 => "0x" + Convert.ToHexString(toBytes).ToLowerInvariant(),
            _ => throw new FormatException($"'to' must be empty or 20 bytes, got {toBytes.Length}."),
        };
        var value = CanonicalUnsigned(items[4].AsBytes(), "value");
        var data = items[5].AsBytes();
        var v = CanonicalUnsigned(items[6].AsBytes(), "v");
        var r = CanonicalUnsigned(items[7].AsBytes(), "r");
        var s = CanonicalUnsigned(items[8].AsBytes(), "s");
        return new ParsedTransaction(nonce, gasPrice, gasLimit, to, value, data, v, r, s);
    }

    private static BigInteger CanonicalUnsigned(byte[] bytes, string field)
    {
        if (bytes.Length > 0 && bytes[0] == 0)
            throw new FormatException($"'{field}' has a leading zero byte (non-canonical integer).");
        return bytes.Length == 0
            ? BigInteger.Zero
            : new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    private static ulong CanonicalUlong(byte[] bytes, string field)
    {
        var value = CanonicalUnsigned(bytes, field);
        return value <= ulong.MaxValue
            ? (ulong)value
            : throw new FormatException($"'{field}' exceeds ulong range.");
    }

    /// <summary>
    /// Re-encodes the EIP-155 signing payload from the parsed fields. Canonical-integer
    /// enforcement in parsing makes decode→encode bijective, and any disagreement with the
    /// signer's encoding surfaces as a failed sender recovery — the signature itself is
    /// the cross-check.
    /// </summary>
    private byte[] EncodeSigningPayload(ParsedTransaction tx)
        => RlpList(
            RlpUnsigned(tx.Nonce), RlpUnsigned(tx.GasPrice), RlpUnsigned(tx.GasLimit),
            RlpBytes(tx.To is null ? [] : FromHexAddress(tx.To)),
            RlpUnsigned(tx.Value), RlpBytes(tx.Data),
            RlpUnsigned(_chainId), RlpUnsigned(BigInteger.Zero), RlpUnsigned(BigInteger.Zero));

    /// <summary>CREATE address: keccak256(rlp([sender, nonce]))[12..].</summary>
    private static string DeriveCreateAddress(string sender, ulong nonce)
    {
        var encoded = RlpList(RlpBytes(FromHexAddress(sender)), RlpUnsigned(nonce));
        return "0x" + Convert.ToHexString(Keccak256.Hash(encoded)[12..]).ToLowerInvariant();
    }

    // Minimal local RLP encoder — kept separate from the library's on purpose.
    private static byte[] RlpBytes(byte[] value)
    {
        if (value.Length == 1 && value[0] < 0x80) return [value[0]];
        if (value.Length <= 55)
            return Concat([(byte)(0x80 + value.Length)], value);
        var len = ToMinimal((ulong)value.Length);
        return Concat([(byte)(0xb7 + len.Length)], len, value);
    }

    private static byte[] RlpUnsigned(BigInteger value)
        => RlpBytes(value.IsZero ? [] : value.ToByteArray(isUnsigned: true, isBigEndian: true));

    private static byte[] RlpUnsigned(ulong value) => RlpUnsigned((BigInteger)value);

    private static byte[] RlpList(params byte[][] encodedItems)
    {
        var payload = Concat(encodedItems);
        if (payload.Length <= 55)
            return Concat([(byte)(0xc0 + payload.Length)], payload);
        var len = ToMinimal((ulong)payload.Length);
        return Concat([(byte)(0xf7 + len.Length)], len, payload);
    }

    private static byte[] ToMinimal(ulong value)
        => value == 0 ? [] : ((BigInteger)value).ToByteArray(isUnsigned: true, isBigEndian: true);

    // ── ABI argument reader (independent of the library's AbiDecoder) ────────

    private sealed class AbiArgs(byte[] args)
    {
        public byte[] Word(int index)
        {
            if (args.Length < (index + 1) * 32)
                throw new RegistryRevertException($"calldata missing argument word {index}");
            return args.AsSpan(index * 32, 32).ToArray();
        }

        public string Address(int index)
        {
            var word = Word(index);
            for (var i = 0; i < 12; i++)
                if (word[i] != 0)
                    throw new RegistryRevertException($"argument {index} is not an address");
            return "0x" + Convert.ToHexString(word[12..]).ToLowerInvariant();
        }

        public BigInteger U256(int index)
            => new(Word(index), isUnsigned: true, isBigEndian: true);

        public byte[] DynamicBytes(int headSlot)
        {
            var offset = U256(headSlot);
            if (offset % 32 != 0 || offset > args.Length - 32)
                throw new RegistryRevertException($"bad dynamic offset in slot {headSlot}");
            var position = (int)offset;
            var length = new BigInteger(args.AsSpan(position, 32), isUnsigned: true, isBigEndian: true);
            if (length > args.Length - position - 32)
                throw new RegistryRevertException("dynamic bytes exceed calldata");
            return args.AsSpan(position + 32, (int)length).ToArray();
        }
    }

    // ── Small helpers ────────────────────────────────────────────────────────

    private static bool TopicsMatch(IReadOnlyList<string[]?>? filterTopics, IReadOnlyList<string> logTopics)
    {
        if (filterTopics is null)
            return true;
        for (var position = 0; position < filterTopics.Count; position++)
        {
            var alternatives = filterTopics[position];
            if (alternatives is null)
                continue;
            if (position >= logTopics.Count)
                return false;
            if (!alternatives.Any(t => string.Equals(t, logTopics[position], StringComparison.OrdinalIgnoreCase)))
                return false;
        }
        return true;
    }

    private static string Normalize(string address) => address.ToLowerInvariant();

    private static byte[] FromHex(string hex)
        => Convert.FromHexString(hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex);

    private static byte[] FromHexAddress(string address)
    {
        var bytes = FromHex(address);
        return bytes.Length == 20
            ? bytes
            : throw new FormatException($"'{address}' is not a 20-byte address.");
    }

    private static byte[] AddressWord(string address)
    {
        var word = new byte[32];
        FromHexAddress(address).CopyTo(word, 12);
        return word;
    }

    private static string AddressFromWord(ReadOnlySpan<byte> word)
        => "0x" + Convert.ToHexString(word[12..]).ToLowerInvariant();

    private static byte[] U256Word(BigInteger value)
    {
        var minimal = value.IsZero ? [] : value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (minimal.Length > 32)
            throw new ArgumentOutOfRangeException(nameof(value), value, "Exceeds uint256.");
        var word = new byte[32];
        minimal.CopyTo(word, 32 - minimal.Length);
        return word;
    }

    private static byte[] U256Word(ulong value) => U256Word((BigInteger)value);

    private static byte[] ScalarBytes(BigInteger scalar)
    {
        var word = new byte[32];
        var minimal = scalar.ToByteArray(isUnsigned: true, isBigEndian: true);
        minimal.CopyTo(word, 32 - minimal.Length);
        return word;
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
