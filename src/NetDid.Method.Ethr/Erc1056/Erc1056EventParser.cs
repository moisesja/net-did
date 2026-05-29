using NetDid.Method.Ethr.Abi;
using NetDid.Method.Ethr.Rpc;

namespace NetDid.Method.Ethr.Erc1056;

/// <summary>
/// Parses a raw <see cref="EthereumLogEntry"/> into a typed <see cref="Erc1056Event"/>.
/// Dispatches on topics[0] and decodes indexed/non-indexed fields.
/// </summary>
public static class Erc1056EventParser
{
    public static Erc1056Event Parse(EthereumLogEntry log)
    {
        ArgumentNullException.ThrowIfNull(log);

        var topic0 = log.Topics[0].ToLowerInvariant();
        var identity = NormalizeAddress(log.Topics[1]);
        var blockNumber = ParseHexUlong(log.BlockNumber);
        var data = DecodeHex(log.Data);

        if (topic0 == Erc1056Topics.DIDOwnerChanged)
        {
            var (owner, prev) = AbiDecoder.DecodeOwnerChangedData(data);
            return new OwnerChangedEvent(
                Identity: identity,
                NewOwner: "0x" + Convert.ToHexString(owner).ToLowerInvariant(),
                PreviousChange: prev,
                BlockNumber: blockNumber);
        }

        if (topic0 == Erc1056Topics.DIDDelegateChanged)
        {
            var (delegateType, del, validTo, prev) = AbiDecoder.DecodeDelegateChangedData(data);
            return new DelegateChangedEvent(
                Identity: identity,
                DelegateType: delegateType,
                Delegate: "0x" + Convert.ToHexString(del).ToLowerInvariant(),
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
        var hex = paddedHex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? paddedHex[2..] : paddedHex;
        // ABI pads addresses to 32 bytes (64 hex chars); last 40 hex chars = 20 bytes
        return "0x" + hex[^40..].ToLowerInvariant();
    }

    private static ulong ParseHexUlong(string hex)
    {
        var clean = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex;
        return Convert.ToUInt64(clean, 16);
    }

    private static byte[] DecodeHex(string hex)
    {
        var clean = hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? hex[2..] : hex;
        return clean.Length == 0 ? [] : Convert.FromHexString(clean);
    }
}
