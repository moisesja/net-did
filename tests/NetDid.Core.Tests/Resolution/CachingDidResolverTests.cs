using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using NSubstitute;
using NetDid.Core.Model;
using NetDid.Core.Resolution;

namespace NetDid.Core.Tests.Resolution;

public class CachingDidResolverTests
{
    private readonly IDidResolver _inner;
    private readonly IMemoryCache _cache;

    public CachingDidResolverTests()
    {
        _inner = Substitute.For<IDidResolver>();
        _cache = new MemoryCache(new MemoryCacheOptions());
    }

    [Fact]
    public async Task ResolveAsync_FirstCall_DelegatesToInner()
    {
        var doc = new DidDocument { Id = new Did("did:key:z6Mk123") };
        var expected = new DidResolutionResult
        {
            DidDocument = doc,
            ResolutionMetadata = new DidResolutionMetadata()
        };
        _inner.ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>()).Returns(expected);

        var resolver = new CachingDidResolver(_inner, _cache);
        var result = await resolver.ResolveAsync("did:key:z6Mk123");

        result.DidDocument.Should().NotBeNull();
        result.DidDocument!.Id.Value.Should().Be("did:key:z6Mk123");
        await _inner.Received(1).ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResolveAsync_SecondCall_ReturnsCachedResult()
    {
        var doc = new DidDocument { Id = new Did("did:key:z6Mk123") };
        var expected = new DidResolutionResult
        {
            DidDocument = doc,
            ResolutionMetadata = new DidResolutionMetadata()
        };
        _inner.ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>()).Returns(expected);

        var resolver = new CachingDidResolver(_inner, _cache);
        await resolver.ResolveAsync("did:key:z6Mk123");
        var result = await resolver.ResolveAsync("did:key:z6Mk123");

        result.DidDocument.Should().NotBeNull();
        // Inner should have been called only once
        await _inner.Received(1).ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResolveAsync_ErrorResult_NotCached()
    {
        var errorResult = DidResolutionResult.NotFound("did:key:z6Mk123");
        _inner.ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>()).Returns(errorResult);

        var resolver = new CachingDidResolver(_inner, _cache);
        await resolver.ResolveAsync("did:key:z6Mk123");
        await resolver.ResolveAsync("did:key:z6Mk123");

        // Inner should have been called twice since error results are not cached
        await _inner.Received(2).ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task ResolveAsync_DifferentOptions_CachedSeparately()
    {
        var doc = new DidDocument { Id = new Did("did:key:z6Mk123") };
        var expected = new DidResolutionResult
        {
            DidDocument = doc,
            ResolutionMetadata = new DidResolutionMetadata()
        };
        _inner.ResolveAsync(Arg.Any<string>(), Arg.Any<DidResolutionOptions?>(), Arg.Any<CancellationToken>())
            .Returns(expected);

        var resolver = new CachingDidResolver(_inner, _cache);
        var optionsA = new DidResolutionOptions { Accept = DidContentTypes.JsonLd };
        var optionsB = new DidResolutionOptions { Accept = DidContentTypes.Json };

        await resolver.ResolveAsync("did:key:z6Mk123", optionsA);
        await resolver.ResolveAsync("did:key:z6Mk123", optionsB);

        // Each set of options should produce a separate call
        await _inner.Received(2).ResolveAsync("did:key:z6Mk123", Arg.Any<DidResolutionOptions?>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public void CanResolve_DelegatesToInner()
    {
        _inner.CanResolve("did:key:z6Mk123").Returns(true);
        _inner.CanResolve("did:web:example.com").Returns(false);

        var resolver = new CachingDidResolver(_inner, _cache);

        resolver.CanResolve("did:key:z6Mk123").Should().BeTrue();
        resolver.CanResolve("did:web:example.com").Should().BeFalse();
    }

    [Fact]
    public async Task ResolveAsync_CustomTtl_Respected()
    {
        var doc = new DidDocument { Id = new Did("did:key:z6Mk123") };
        var expected = new DidResolutionResult
        {
            DidDocument = doc,
            ResolutionMetadata = new DidResolutionMetadata()
        };
        _inner.ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>()).Returns(expected);

        // Very short TTL — the cache decorator should still function
        var resolver = new CachingDidResolver(_inner, _cache, ttl: TimeSpan.FromHours(1));
        await resolver.ResolveAsync("did:key:z6Mk123");
        var result = await resolver.ResolveAsync("did:key:z6Mk123");

        result.DidDocument.Should().NotBeNull();
        await _inner.Received(1).ResolveAsync("did:key:z6Mk123", null, Arg.Any<CancellationToken>());
    }
}
