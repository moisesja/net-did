using System.Reflection;

namespace NetDid.Method.Ethr.Deployment;

/// <summary>
/// The ERC-1056 <c>EthereumDIDRegistry</c> contract, vendored for deployment to
/// private / consortium / development EVM chains.
///
/// <para>
/// On public networks the registry is <b>already deployed</b> at the well-known addresses
/// in <see cref="Rpc.KnownNetworks"/> — nothing to deploy. This type exists for every
/// other EVM chain: deploy the registry once, then use the resulting address in an
/// <see cref="Rpc.EthereumNetworkConfig"/>.
/// </para>
///
/// <para><b>Provenance.</b> The embedded creation bytecode is copied verbatim from the
/// official npm artifacts (MIT-licensed, uport-project/ethr-did-registry):</para>
/// <list type="bullet">
///   <item><description><b>Modern</b> — <c>ethr-did-registry@1.3.0</c>,
///   <c>artifacts/contracts/EthereumDIDRegistry.sol/EthereumDIDRegistry.json → bytecode</c>
///   (Hardhat artifact, solc 0.8.6 source generation; the contract behind the
///   <c>0x03d5003b…</c> deployments, <c>LegacyNonce = false</c>).</description></item>
///   <item><description><b>Legacy</b> — <c>ethr-did-registry@0.0.3</c>,
///   <c>build/contracts/EthereumDIDRegistry.json → bytecode</c> (Truffle artifact,
///   solc 0.4.24; its <c>networks</c> map records the mainnet <c>0xdca7ef03…</c>
///   deployment this generation is known by, <c>LegacyNonce = true</c>).</description></item>
/// </list>
/// <para>A unit test pins the keccak256 of each embedded artifact so the bytes cannot
/// drift silently.</para>
/// </summary>
public static class Erc1056Registry
{
    private static readonly Lazy<byte[]> _modern = new(() => Load("ethr-did-registry-1.3.0.creation.hex"));
    private static readonly Lazy<byte[]> _legacy = new(() => Load("ethr-did-registry-0.0.3.creation.hex"));

    /// <summary>Creation bytecode of the modern (1.x) registry — <c>LegacyNonce = false</c>.</summary>
    public static ReadOnlyMemory<byte> ModernCreationBytecode => _modern.Value;

    /// <summary>Creation bytecode of the legacy (0.0.3) registry — <c>LegacyNonce = true</c>.</summary>
    public static ReadOnlyMemory<byte> LegacyCreationBytecode => _legacy.Value;

    private static byte[] Load(string resourceName)
    {
        var assembly = typeof(Erc1056Registry).Assembly;
        var fullName = $"NetDid.Method.Ethr.Deployment.{resourceName}";
        using var stream = assembly.GetManifestResourceStream(fullName)
            ?? throw new InvalidOperationException($"Embedded resource '{fullName}' is missing.");
        using var reader = new StreamReader(stream);
        return Convert.FromHexString(reader.ReadToEnd().Trim());
    }
}
