using System.Net;
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
