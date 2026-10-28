using System.Text;
using DotNet.Testcontainers.Builders;
using DotNet.Testcontainers.Containers;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.IntegrationTests;

/// <summary>
/// Marks a test that needs a real EVM. Skipped unless <c>NETDID_ETHR_INTEGRATION=1</c>,
/// so the default <c>dotnet test</c> run stays offline. Setting the variable is an explicit
/// request for real-EVM coverage: once opted in, Docker must be reachable — the suite fails
/// with one actionable message rather than silently skipping (issue #112).
/// </summary>
public sealed class EthrIntegrationFactAttribute : FactAttribute
{
    public EthrIntegrationFactAttribute()
        : this(Environment.GetEnvironmentVariable("NETDID_ETHR_INTEGRATION"))
    {
    }

    // Test seam (issue #112): lets the gate tests exercise the skip decision for any value
    // without mutating process environment, which could race this assembly's fixture
    // initialization under runner configs that re-enable collection parallelism.
    internal EthrIntegrationFactAttribute(string? optIn)
    {
        if (optIn != "1")
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

        _container = await StartWithHonestDockerFailureAsync(async () =>
        {
            var container = new ContainerBuilder(Image)
                .WithEntrypoint("anvil")
                .WithCommand("--host", "0.0.0.0", "--port", "8545", "--chain-id", ChainId.ToString())
                .WithPortBinding(8545, assignRandomHostPort: true)
                .WithWaitStrategy(Wait.ForUnixContainer().UntilInternalTcpPortIsAvailable(8545))
                .Build();
            await container.StartAsync();
            return container;
        });

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

    /// <summary>
    /// Runs the container start, mapping "no usable Docker endpoint" (issue #112) to the one
    /// actionable failure. Any other startup failure (image pull, wait strategy, a daemon that
    /// died after endpoint detection) is a different diagnosis and propagates untouched.
    /// </summary>
    internal static async Task<IContainer> StartWithHonestDockerFailureAsync(Func<Task<IContainer>> start)
    {
        try
        {
            return await start();
        }
        catch (DockerUnavailableException ex)
        {
            throw DockerUnreachableFailure(ex);
        }
    }

    /// <summary>
    /// One actionable failure for "opted in, but Docker is unreachable" (issue #112). The
    /// Testcontainers message (which lists every endpoint it tried) and the inner-exception
    /// chain (which holds each endpoint's failure reason, e.g. permission denied vs connection
    /// refused) are embedded as text; the original exception is deliberately NOT kept as
    /// InnerException — its deep async stacks are the noise this replaces, and xUnit reports a
    /// collection-fixture failure once per test.
    /// </summary>
    internal static InvalidOperationException DockerUnreachableFailure(DockerUnavailableException ex)
    {
        var message = new StringBuilder()
            .Append("NETDID_ETHR_INTEGRATION=1 is set, but Docker is not reachable, so the real-EVM ")
            .Append("integration suite cannot run. Opting in requests coverage, so the suite fails rather ")
            .Append("than skips. Start Docker (or unset NETDID_ETHR_INTEGRATION) and re-run. ")
            .Append("Testcontainers reported: ").Append(ex.Message);

        IEnumerable<Exception> causes = ex.InnerException switch
        {
            AggregateException aggregate => aggregate.Flatten().InnerExceptions,
            { } single => new[] { single },
            null => Array.Empty<Exception>(),
        };
        foreach (var cause in causes)
            for (var c = (Exception?)cause; c is not null; c = c.InnerException)
                message.AppendLine().Append("Underlying cause: ").Append(c.GetType().Name).Append(": ").Append(c.Message);

        return new InvalidOperationException(message.ToString());
    }
}

[CollectionDefinition("anvil")]
public sealed class AnvilCollection : ICollectionFixture<AnvilFixture>;
