using NetDid.Method.Ethr.Abi;
using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr.Erc1056;

/// <summary>
/// Parses a raw <see cref="EthereumLogEntry"/> into a typed <see cref="Erc1056Event"/>.
/// Dispatches on topics[0] and decodes indexed/non-indexed fields.
/// </summary>
public static class Erc1056EventParser
{
    private const string HexPrefix = "0x";

    public static Erc1056Event Parse(EthereumLogEntry log)
    {
        ArgumentNullException.ThrowIfNull(log);

        if (log.Topics.Count != 2)
            throw new ArgumentException(
                $"ERC-1056 logs must contain exactly two topics, got {log.Topics.Count}.",
                nameof(log));

        var topic0 = NormalizeTopic(log.Topics[0], "event signature");
        var identity = NormalizeAddress(log.Topics[1]);
        var blockNumber = ParseCanonicalHexQuantity(log.BlockNumber, "blockNumber");
        var data = DecodeHex(log.Data);

        if (topic0 == Erc1056Topics.DIDOwnerChanged)
        {
            var (owner, prev) = AbiDecoder.DecodeOwnerChangedData(data);
            return new OwnerChangedEvent(
                Identity: identity,
                NewOwner: HexPrefix + Convert.ToHexString(owner).ToLowerInvariant(),
                PreviousChange: prev,
                BlockNumber: blockNumber);
        }

        if (topic0 == Erc1056Topics.DIDDelegateChanged)
        {
            var (delegateType, del, validTo, prev) = AbiDecoder.DecodeDelegateChangedData(data);
            return new DelegateChangedEvent(
                Identity: identity,
                DelegateType: delegateType,
                Delegate: HexPrefix + Convert.ToHexString(del).ToLowerInvariant(),
                ValidTo: validTo,
                PreviousChange: prev,
                BlockNumber: blockNumber);
        }

        if (topic0 == Erc1056Topics.DIDAttributeChanged)
        {
            var (name, value, validTo, prev) = AbiDecoder.DecodeAttributeChangedData(data);
            return new AttributeChangedEvent(
                Identity: identity,
                Name: name,
                Value: value,
                ValidTo: validTo,
                PreviousChange: prev,
                BlockNumber: blockNumber);
        }

        throw new ArgumentException($"Unknown ERC-1056 topic: {log.Topics[0]}", nameof(log));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Normalises an ABI-indexed address topic (32-byte padded hex) to a lowercase
    /// 0x-prefixed 20-byte address string.
    /// </summary>
    private static string NormalizeAddress(string paddedHex)
    {
        var hex = NormalizeTopic(paddedHex, "identity")[2..];
        if (!hex[..24].All(c => c == '0'))
            throw new ArgumentException(
                "ERC-1056 identity topic has non-zero address padding.",
                nameof(paddedHex));
        return HexPrefix + hex[24..].ToLowerInvariant();
    }

    private static string NormalizeTopic(string topic, string context)
    {
        if (!topic.StartsWith(HexPrefix, StringComparison.Ordinal)
            || topic.Length != 66
            || !IsLowerHex(topic.AsSpan(2)))
            throw new ArgumentException(
                $"ERC-1056 {context} topic must be a canonical lowercase 0x-prefixed 32-byte hex value.",
                nameof(topic));
        try
        {
            _ = Convert.FromHexString(topic[2..]);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException(
                $"ERC-1056 {context} topic contains invalid hex.", nameof(topic), ex);
        }
        return topic;
    }

    private static ulong ParseCanonicalHexQuantity(string value, string context)
    {
        if (!value.StartsWith(HexPrefix, StringComparison.Ordinal)
            || value.Length == 2
            || (value.Length > 3 && value[2] == '0')
            || !IsLowerHex(value.AsSpan(2)))
            throw new ArgumentException(
                $"{context} must be a canonical 0x-prefixed Ethereum quantity.",
                nameof(value));
        try
        {
            return Convert.ToUInt64(value[2..], 16);
        }
        catch (Exception ex) when (ex is FormatException or OverflowException)
        {
            throw new ArgumentException(
                $"{context} is not a valid Ethereum quantity.", nameof(value), ex);
        }
    }

    private static byte[] DecodeHex(string hex)
    {
        if (!hex.StartsWith(HexPrefix, StringComparison.Ordinal)
            || (hex.Length - 2) % 2 != 0
            || !IsLowerHex(hex.AsSpan(2)))
            throw new ArgumentException(
                "ERC-1056 data must be a 0x-prefixed, whole-byte hex value.",
                nameof(hex));
        try
        {
            return hex.Length == 2 ? [] : Convert.FromHexString(hex[2..]);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("ERC-1056 data contains invalid hex.", nameof(hex), ex);
        }
    }

    private static bool IsLowerHex(ReadOnlySpan<char> value)
    {
        foreach (var c in value)
        {
            if (!char.IsAsciiDigit(c) && c is not (>= 'a' and <= 'f'))
                return false;
        }
        return true;
    }
}
