using FluentAssertions;
using NSubstitute;
using NetDid.Core.Model;
using NetDid.Core.Resolution;

namespace NetDid.Core.Tests.Resolution;

public class CompositeDidResolverTests
{
    private static IDidMethod CreateMockMethod(string methodName, DidDocument? docToReturn = null)
    {
        var method = Substitute.For<IDidMethod>();
        method.MethodName.Returns(methodName);

        var result = docToReturn is not null
            ? new DidResolutionResult
            {
                DidDocument = docToReturn,
                ResolutionMetadata = new DidResolutionMetadata { ContentType = DidContentTypes.JsonLd }
            }
            : DidResolutionResult.NotFound($"did:{methodName}:xxx");

        method.ResolveAsync(Arg.Any<string>(), Arg.Any<DidResolutionOptions?>(), Arg.Any<CancellationToken>())
            .Returns(result);

        return method;
    }

    [Fact]
    public void CanResolve_RegisteredMethod_ReturnsTrue()
    {
        var method = CreateMockMethod("key");
        var resolver = new CompositeDidResolver(new[] { method });

        resolver.CanResolve("did:key:z6Mk123").Should().BeTrue();
    }

    [Fact]
    public void CanResolve_UnregisteredMethod_ReturnsFalse()
    {
        var method = CreateMockMethod("key");
        var resolver = new CompositeDidResolver(new[] { method });

        resolver.CanResolve("did:web:example.com").Should().BeFalse();
    }

    [Fact]
    public void CanResolve_InvalidDid_ReturnsFalse()
    {
        var method = CreateMockMethod("key");
        var resolver = new CompositeDidResolver(new[] { method });

        resolver.CanResolve("not-a-did").Should().BeFalse();
    }

    [Fact]
    public async Task ResolveAsync_RegisteredMethod_DelegatesToMethod()
    {
        var doc = new DidDocument { Id = new Did("did:key:z6Mk123") };
        var method = CreateMockMethod("key", doc);
        var resolver = new CompositeDidResolver(new[] { method });

        var result = await resolver.ResolveAsync("did:key:z6Mk123");

        result.DidDocument.Should().NotBeNull();
        result.DidDocument!.Id.Value.Should().Be("did:key:z6Mk123");
    }

    [Fact]
    public async Task ResolveAsync_UnregisteredMethod_ReturnsMethodNotSupported()
    {
        var method = CreateMockMethod("key");
        var resolver = new CompositeDidResolver(new[] { method });

        var result = await resolver.ResolveAsync("did:web:example.com");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("methodNotSupported");
    }

    [Fact]
    public async Task ResolveAsync_InvalidDid_ReturnsMethodNotSupported()
    {
        var method = CreateMockMethod("key");
        var resolver = new CompositeDidResolver(new[] { method });

        var result = await resolver.ResolveAsync("not-a-did");

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("methodNotSupported");
    }

    [Fact]
    public async Task ResolveAsync_MultipleRegisteredMethods_RoutesCorrectly()
    {
        var keyDoc = new DidDocument { Id = new Did("did:key:z6Mk123") };
        var peerDoc = new DidDocument { Id = new Did("did:peer:2abc") };

        var keyMethod = CreateMockMethod("key", keyDoc);
        var peerMethod = CreateMockMethod("peer", peerDoc);
        var resolver = new CompositeDidResolver(new[] { keyMethod, peerMethod });

        var keyResult = await resolver.ResolveAsync("did:key:z6Mk123");
        var peerResult = await resolver.ResolveAsync("did:peer:2abc");

        keyResult.DidDocument!.Id.Value.Should().Be("did:key:z6Mk123");
        peerResult.DidDocument!.Id.Value.Should().Be("did:peer:2abc");
    }

    [Fact]
    public async Task ResolveAsync_PassesOptionsThroughToMethod()
    {
        var method = CreateMockMethod("key");
        var resolver = new CompositeDidResolver(new[] { method });
        var options = new DidResolutionOptions { Accept = DidContentTypes.Json };

        await resolver.ResolveAsync("did:key:z6Mk123", options);

        await method.Received(1).ResolveAsync("did:key:z6Mk123", options, Arg.Any<CancellationToken>());
    }
}
