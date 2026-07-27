using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.IntegrationTests;

/// <summary>
/// Marks a test that needs a real EVM. Skipped unless <c>NETDID_ETHR_INTEGRATION=1</c>
/// (and Docker is reachable), so the default <c>dotnet test</c> run stays offline.
/// </summary>
public sealed class EthrIntegrationFactAttribute : FactAttribute
{
    public EthrIntegrationFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("NETDID_ETHR_INTEGRATION") != "1")
            Skip = "Real-EVM integration tests are opt-in: set NETDID_ETHR_INTEGRATION=1 (requires Docker).";
    }
}

/// <summary>
/// One Anvil (Foundry) container per test collection — the real-EVM oracle. Provides an
/// RPC client plus Anvil's first two pre-funded dev accounts (the public well-known
/// test mnemonic; these keys hold value on no real network).
/// </summary>
public sealed class AnvilFixture : IAsyncLifetime
{
    // Pinned for reproducibility; anvil 1.7.1.
    private const string Image = "ghcr.io/foundry-rs/foundry:v1.7.1";

    public const ulong ChainId = 31337;

    /// <summary>Anvil dev account #0 (0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266).</summary>
    public static readonly byte[] FunderKey = Convert.FromHexString(
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    /// <summary>Anvil dev account #1 (0x70997970C51812dc3A010C7d01b50e0d17dc79C8).</summary>
    public static readonly byte[] SecondKey = Convert.FromHexString(
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");

    private IContainer? _container;

    public string RpcUrl { get; private set; } = "";

    public DefaultEthereumRpcClient Client { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        if (Environment.GetEnvironmentVariable("NETDID_ETHR_INTEGRATION") != "1")
            return; // every test in the collection is skipped; don't touch Docker

        _container = new ContainerBuilder(Image)
            .WithEntrypoint("anvil")
            .WithCommand("--host", "0.0.0.0", "--port", "8545", "--chain-id", ChainId.ToString())
            .WithPortBinding(8545, assignRandomHostPort: true)
            .WithWaitStrategy(Wait.ForUnixContainer().UntilInternalTcpPortIsAvailable(8545))
            .Build();
        await _container.StartAsync();

        RpcUrl = $"http://{_container.Hostname}:{_container.GetMappedPublicPort(8545)}";
        Client = new DefaultEthereumRpcClient(new HttpClient { BaseAddress = new Uri(RpcUrl) });

        // The port can open a beat before the JSON-RPC loop serves; poll briefly.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                if (await Client.GetChainIdAsync() != ChainId)
                    throw new InvalidOperationException("Unexpected chain id from anvil.");
                break;
            }
            catch when (attempt < 20)
            {
                await Task.Delay(250);
            }
        }
    }

    public async Task DisposeAsync()
    {
        if (_container is not null)
            await _container.DisposeAsync();
    }
}

[CollectionDefinition("anvil")]
public sealed class AnvilCollection : ICollectionFixture<AnvilFixture>;
