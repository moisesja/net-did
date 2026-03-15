using FluentAssertions;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NSubstitute;

namespace NetDid.Core.Tests;

public class DidManagerTests
{
    private sealed record StubCreateOptions : DidCreateOptions
    {
        public override string MethodName => "key";
    }
    private sealed record StubUpdateOptions : DidUpdateOptions;
    private sealed record StubDeactivateOptions : DidDeactivateOptions;

    private readonly IDidMethod _keyMethod;
    private readonly IDidMethod _peerMethod;
    private readonly DidManager _manager;

    public DidManagerTests()
    {
        _keyMethod = Substitute.For<IDidMethod>();
        _keyMethod.MethodName.Returns("key");

        _peerMethod = Substitute.For<IDidMethod>();
        _peerMethod.MethodName.Returns("peer");

        _manager = new DidManager([_keyMethod, _peerMethod]);
    }

    [Fact]
    public void RegisteredMethods_ReturnsAllMethodNames()
    {
        _manager.RegisteredMethods.Should().BeEquivalentTo(["key", "peer"]);
    }

    [Fact]
    public void GetMethod_ReturnsCorrectMethod()
    {
        _manager.GetMethod("key").Should().BeSameAs(_keyMethod);
        _manager.GetMethod("peer").Should().BeSameAs(_peerMethod);
    }

    [Fact]
    public void GetMethod_ReturnsNullForUnregistered()
    {
        _manager.GetMethod("webvh").Should().BeNull();
    }

    [Fact]
    public async Task CreateAsync_RoutesToCorrectMethod()
    {
        var options = new StubCreateOptions();
        var expected = new DidCreateResult
        {
            Did = new Did("did:key:z6MkTest"),
            DidDocument = new DidDocument { Id = new Did("did:key:z6MkTest") }
        };

        _keyMethod.CreateAsync(options, Arg.Any<CancellationToken>())
            .Returns(expected);

        var result = await _manager.CreateAsync(options);

        result.Should().BeSameAs(expected);
    }

    private sealed record UnregisteredCreateOptions : DidCreateOptions
    {
        public override string MethodName => "ethr";
    }

    [Fact]
    public async Task CreateAsync_ThrowsForUnregisteredMethod()
    {
        var act = () => _manager.CreateAsync(new UnregisteredCreateOptions());

        await act.Should().ThrowAsync<MethodNotSupportedException>()
            .WithMessage("*ethr*");
    }

    [Fact]
    public async Task ResolveAsync_RoutesToCorrectMethod()
    {
        var did = "did:peer:0z6MkTest";
        var expected = new DidResolutionResult
        {
            DidDocument = new DidDocument { Id = new Did(did) },
            ResolutionMetadata = new DidResolutionMetadata()
        };

        _peerMethod.ResolveAsync(did, null, Arg.Any<CancellationToken>())
            .Returns(expected);

        var result = await _manager.ResolveAsync(did);

        result.Should().BeSameAs(expected);
    }

    [Fact]
    public async Task ResolveAsync_ReturnsMethodNotSupportedForUnregistered()
    {
        var result = await _manager.ResolveAsync("did:webvh:test:example.com");

        result.ResolutionMetadata.Error.Should().Be("methodNotSupported");
    }

    [Fact]
    public async Task UpdateAsync_RoutesToCorrectMethod()
    {
        var did = "did:key:z6MkTest";
        var options = new StubUpdateOptions();
        var expected = new DidUpdateResult
        {
            DidDocument = new DidDocument { Id = new Did(did) }
        };

        _keyMethod.UpdateAsync(did, options, Arg.Any<CancellationToken>())
            .Returns(expected);

        var result = await _manager.UpdateAsync(did, options);

        result.Should().BeSameAs(expected);
    }

    [Fact]
    public async Task UpdateAsync_ThrowsForUnregisteredMethod()
    {
        var act = () => _manager.UpdateAsync("did:ethr:0x123", new StubUpdateOptions());

        await act.Should().ThrowAsync<MethodNotSupportedException>();
    }

    [Fact]
    public async Task DeactivateAsync_RoutesToCorrectMethod()
    {
        var did = "did:key:z6MkTest";
        var options = new StubDeactivateOptions();
        var expected = new DidDeactivateResult { Success = true };

        _keyMethod.DeactivateAsync(did, options, Arg.Any<CancellationToken>())
            .Returns(expected);

        var result = await _manager.DeactivateAsync(did, options);

        result.Should().BeSameAs(expected);
    }

    [Fact]
    public async Task DeactivateAsync_ThrowsForUnregisteredMethod()
    {
        var act = () => _manager.DeactivateAsync("did:ethr:0x123", new StubDeactivateOptions());

        await act.Should().ThrowAsync<MethodNotSupportedException>();
    }

    [Fact]
    public void CanResolve_ReturnsTrueForRegistered()
    {
        _manager.CanResolve("did:key:z6MkTest").Should().BeTrue();
        _manager.CanResolve("did:peer:0z6MkTest").Should().BeTrue();
    }

    [Fact]
    public void CanResolve_ReturnsFalseForUnregistered()
    {
        _manager.CanResolve("did:ethr:0x123").Should().BeFalse();
    }

    [Fact]
    public void CanResolve_ReturnsFalseForInvalidDid()
    {
        _manager.CanResolve("not-a-did").Should().BeFalse();
    }

    [Fact]
    public void ImplementsIDidResolver()
    {
        _manager.Should().BeAssignableTo<IDidResolver>();
    }
}
