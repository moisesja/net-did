using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Model;
using NetDid.Core.Resolution;
using NetDid.Extensions.DependencyInjection;
using NetDid.Method.Key;

namespace NetDid.Extensions.DependencyInjection.Tests;

public class ServiceRegistrationTests
{
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

        var result = await manager.CreateAsync("key", new DidKeyCreateOptions
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
        var created = await manager.CreateAsync("key", new DidKeyCreateOptions
        {
            KeyType = KeyType.Ed25519
        });

        var resolved = await manager.ResolveAsync(created.Did.Value);

        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.Id.Should().Be(created.Did);
    }
}
