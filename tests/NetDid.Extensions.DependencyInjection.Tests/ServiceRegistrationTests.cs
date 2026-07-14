using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetDid.Core;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Extensions.DependencyInjection;
using NetDid.Method.Key;
using NetDid.Method.WebVh;

namespace NetDid.Extensions.DependencyInjection.Tests;

public class ServiceRegistrationTests
{
    [Fact]
    public void AddDidWebVh_ConfiguresSecurePrimaryHandler()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidWebVh());
        using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpMessageHandlerFactory>();

        var handler = factory.CreateHandler(typeof(DefaultWebVhHttpClient).Name);
        while (handler is DelegatingHandler delegating)
            handler = delegating.InnerHandler;

        var primary = handler.Should().BeOfType<SocketsHttpHandler>().Subject;
        primary.AllowAutoRedirect.Should().BeFalse();
        primary.UseProxy.Should().BeFalse();
        primary.ConnectCallback.Should().NotBeNull();
    }

    [Fact]
    public async Task AddDidWebVh_FlowsCustomOptionsIntoClient()
    {
        // A 16-byte body must be rejected by a client built with a 4-byte
        // limit, proving the options passed to AddDidWebVh reach the typed
        // client through the IHttpClientFactory.
        var services = new ServiceCollection();
        services.AddNetDid(builder =>
            builder.AddDidWebVh(new WebVhHttpClientOptions { MaxDidLogBytes = 4 }));
        services.AddHttpClient<DefaultWebVhHttpClient>()
            .ConfigurePrimaryHttpMessageHandler(() => new FixedBodyHandler(new byte[16]));
        var provider = services.BuildServiceProvider();

        var client = provider.GetRequiredService<IWebVhHttpClient>();
        var result = await client.FetchDidLogAsync(
            new Uri("https://example.com/.well-known/did.jsonl"));

        result.Should().BeNull();
    }

    [Fact]
    public async Task AddDidWebVh_FlowsCustomTimeoutIntoClient()
    {
        // A handler that never responds must be abandoned once the configured
        // Timeout elapses, proving the timeout passed to AddDidWebVh reaches
        // the typed client through the IHttpClientFactory (issue #80).
        var services = new ServiceCollection();
        services.AddNetDid(builder =>
            builder.AddDidWebVh(new WebVhHttpClientOptions
            {
                Timeout = TimeSpan.FromMilliseconds(100)
            }));
        services.AddHttpClient<DefaultWebVhHttpClient>()
            .ConfigurePrimaryHttpMessageHandler(() => new NeverRespondingHandler());
        var provider = services.BuildServiceProvider();

        var client = provider.GetRequiredService<IWebVhHttpClient>();
        var result = await client.FetchDidLogAsync(
            new Uri("https://example.com/.well-known/did.jsonl"));

        result.Should().BeNull();
    }

    [Fact]
    public void AddDidWebVh_NeutralizesHttpClientTimeout()
    {
        // The factory-built typed client must carry Timeout = infinite so that
        // WebVhHttpClientOptions.Timeout is the sole time authority — otherwise
        // HttpClient.Timeout's 100s framework default would silently cap any
        // configured value above it.
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidWebVh());
        var provider = services.BuildServiceProvider();

        // Typed clients register under the type's name; CreateClient applies
        // every ConfigureHttpClient action from AddDidWebVh.
        var factory = provider.GetRequiredService<IHttpClientFactory>();
        var http = factory.CreateClient(nameof(DefaultWebVhHttpClient));

        http.Timeout.Should().Be(Timeout.InfiniteTimeSpan);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Issue101_AddDidWebVh_RejectsControllerProofBudgetBelowOne(int invalidBudget)
    {
        var services = new ServiceCollection();

        var act = () => services.AddNetDid(builder =>
            builder.AddDidWebVh(
                httpClientOptions: null,
                maxControllerProofsPerEntry: invalidBudget));

        act.Should().Throw<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be("maxControllerProofsPerEntry");
    }

    [Fact]
    public async Task Issue101_AddDidWebVh_FlowsRaisedControllerProofBudgetIntoMethod()
    {
        const int raisedBudget = 9;
        var logClient = new FixedLogWebVhHttpClient();
        var services = new ServiceCollection();
        services.AddNetDid(builder =>
            builder.AddDidWebVh(
                httpClientOptions: null,
                maxControllerProofsPerEntry: raisedBudget));

        // The last registration is the client consumed by the deferred IDidMethod factory.
        services.AddSingleton<IWebVhHttpClient>(logClient);
        using var provider = services.BuildServiceProvider();
        var method = provider.GetServices<IDidMethod>()
            .Single(candidate => candidate.MethodName == "webvh");

        var key = provider.GetRequiredService<IKeyGenerator>().Generate(KeyType.Ed25519);
        var signer = new KeyPairSigner(
            key,
            provider.GetRequiredService<ICryptoProvider>());
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        var log = (string)created.Artifacts![DidWebVhArtifacts.DidJsonl];
        var genesis = JsonNode.Parse(log)!.AsObject();
        var originalProof = genesis["proof"]!.AsArray().Single()!;
        var proofs = new JsonArray();
        for (var i = 0; i < raisedBudget; i++)
            proofs.Add(originalProof.DeepClone());
        genesis["proof"] = proofs;
        logClient.DidLog = Encoding.UTF8.GetBytes(genesis.ToJsonString());

        var resolved = await method.ResolveAsync(created.Did.Value);

        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public void Issue101_ExistingUntypedDefaultWebVhOptionsCall_RemainsSourceCompatible()
    {
        var services = new ServiceCollection();

        services.AddNetDid(builder => builder.AddDidWebVh(default));

        using var provider = services.BuildServiceProvider();
        provider.GetServices<IDidMethod>()
            .Should().ContainSingle(method => method.MethodName == "webvh");
    }

    private sealed class FixedBodyHandler(byte[] body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(body)
            });
    }

    private sealed class NeverRespondingHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    private sealed class FixedLogWebVhHttpClient : IWebVhHttpClient
    {
        public byte[]? DidLog { get; set; }

        public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default)
            => Task.FromResult(DidLog);

        public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default)
            => Task.FromResult<byte[]?>(null);
    }

    [Fact]
    public void AddNetDid_RegistersSharedInfrastructure()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidKey());
        var provider = services.BuildServiceProvider();

        provider.GetService<IKeyGenerator>().Should().NotBeNull();
        provider.GetService<ICryptoProvider>().Should().NotBeNull();
    }

    [Fact]
    public void AddNetDid_RegistersIDidResolver()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidKey());
        var provider = services.BuildServiceProvider();

        var resolver = provider.GetService<IDidResolver>();
        resolver.Should().NotBeNull();
        resolver.Should().BeOfType<CompositeDidResolver>();
    }

    [Fact]
    public void AddNetDid_RegistersIDidManager()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidKey());
        var provider = services.BuildServiceProvider();

        var manager = provider.GetService<IDidManager>();
        manager.Should().NotBeNull();
        manager.Should().BeOfType<DidManager>();
    }

    [Fact]
    public void AddDidKey_RegistersDidKeyMethod()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidKey());
        var provider = services.BuildServiceProvider();

        var manager = provider.GetRequiredService<IDidManager>();
        manager.GetMethod("key").Should().NotBeNull();
        manager.GetMethod("key").Should().BeOfType<DidKeyMethod>();
    }

    [Fact]
    public void AddDidPeer_RegistersDidPeerMethod()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidPeer());
        var provider = services.BuildServiceProvider();

        var manager = provider.GetRequiredService<IDidManager>();
        manager.GetMethod("peer").Should().NotBeNull();
    }

    [Fact]
    public void AddMultipleMethods_AllRegistered()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder =>
        {
            builder.AddDidKey();
            builder.AddDidPeer();
        });
        var provider = services.BuildServiceProvider();

        var manager = provider.GetRequiredService<IDidManager>();
        manager.RegisteredMethods.Should().BeEquivalentTo(["key", "peer"]);
    }

    [Fact]
    public void AddCaching_WrapsCachingResolver()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder =>
        {
            builder.AddDidKey();
            builder.AddCaching(TimeSpan.FromMinutes(5));
        });
        var provider = services.BuildServiceProvider();

        var resolver = provider.GetRequiredService<IDidResolver>();
        resolver.Should().BeOfType<CachingDidResolver>();
    }

    [Fact]
    public async Task ResolverCanResolve_DidKey()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidKey());
        var provider = services.BuildServiceProvider();

        var resolver = provider.GetRequiredService<IDidResolver>();
        resolver.CanResolve("did:key:z6MkTest").Should().BeTrue();
        resolver.CanResolve("did:peer:0z6MkTest").Should().BeFalse();
    }

    [Fact]
    public async Task ManagerCanCreate_DidKey()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidKey());
        var provider = services.BuildServiceProvider();

        var manager = provider.GetRequiredService<IDidManager>();

        var result = await manager.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.Ed25519
        });

        result.Did.Value.Should().StartWith("did:key:z6Mk");
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task ManagerCanResolve_DidKey()
    {
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidKey());
        var provider = services.BuildServiceProvider();

        var manager = provider.GetRequiredService<IDidManager>();

        // Create then resolve
        var created = await manager.CreateAsync(new DidKeyCreateOptions
        {
            KeyType = KeyType.Ed25519
        });

        var resolved = await manager.ResolveAsync(created.Did.Value);

        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.Id.Should().Be(created.Did);
    }
}
