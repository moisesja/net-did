using System.Net;
using System.Text;
using FluentAssertions;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Trust-boundary tests for the JSON-RPC client against an UNTRUSTED node.
/// Malformed / oversize responses must surface as <see cref="EthereumInteractionException"/>
/// at this boundary (never a raw JsonException / NullReferenceException, never an OOM).
/// Findings 3 &amp; 4 from the PR #70 adoption adversarial review.
/// </summary>
public class DefaultEthereumRpcClientTests
{
    private const long CapBytes = 16L * 1024 * 1024;

    private static DefaultEthereumRpcClient ClientReturning(
        HttpStatusCode status, HttpContent content)
    {
        var handler = new StubHandler(_ =>
            new HttpResponseMessage(status) { Content = content });
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://rpc.local") };
        return new DefaultEthereumRpcClient(http);
    }

    // ── Finding 3: malformed JSON body → EthereumInteractionException ─────────────

    [Fact]
    public async Task GetChainId_MalformedJsonBody_ThrowsEthereumInteractionException()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent("this is not json"));

        var act = () => client.GetChainIdAsync();

        (await act.Should().ThrowAsync<EthereumInteractionException>())
            .WithMessage("*Malformed JSON*");
    }

    [Fact]
    public async Task GetChainId_MissingResultField_ThrowsEthereumInteractionException()
    {
        var client = ClientReturning(HttpStatusCode.OK,
            new StringContent("{\"jsonrpc\":\"2.0\",\"id\":1}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*No 'result' field*");
    }

    [Fact]
    public async Task GetChainId_RpcErrorObject_ThrowsEthereumInteractionException()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"boom\"}}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*RPC error*");
    }

    [Fact]
    public async Task GetChainId_HttpErrorStatus_ThrowsEthereumInteractionException()
    {
        var client = ClientReturning(HttpStatusCode.InternalServerError, new StringContent("{}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*HTTP error 500*");
    }

    // ── Finding 4: oversize response is rejected, not buffered ────────────────────

    [Fact]
    public async Task GetChainId_DeclaredContentLengthOverCap_ThrowsBeforeBuffering()
    {
        var content = new StringContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}");
        content.Headers.ContentLength = CapBytes + 1; // hostile node over-declares

        var client = ClientReturning(HttpStatusCode.OK, content);

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*exceeding the*cap*");
    }

    [Fact]
    public async Task GetChainId_StreamedBodyOverCap_UndeclaredLength_ThrowsAtByteCap()
    {
        // A node that omits Content-Length and streams more than the cap must still be
        // stopped by the running byte count, not allowed to exhaust memory.
        var client = ClientReturning(HttpStatusCode.OK, new OversizeStreamedContent(CapBytes + 4096));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*exceeded the*cap*");
    }

    // ── Sanity: a well-formed response still works ────────────────────────────────

    [Fact]
    public async Task GetChainId_WellFormed_ReturnsValue()
    {
        var client = ClientReturning(HttpStatusCode.OK,
            new StringContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0xaa36a7\"}"));

        var chainId = await client.GetChainIdAsync();

        chainId.Should().Be(0xaa36a7UL);
    }

    // ── Stubs ─────────────────────────────────────────────────────────────────────

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(responder(request));
    }

    /// <summary>Streams <paramref name="length"/> bytes with no Content-Length header.</summary>
    private sealed class OversizeStreamedContent : HttpContent
    {
        private readonly long _length;
        public OversizeStreamedContent(long length) => _length = length;

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            var chunk = Encoding.ASCII.GetBytes(new string('a', 65536));
            long written = 0;
            while (written < _length)
            {
                await stream.WriteAsync(chunk);
                written += chunk.Length;
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false; // force chunked / undeclared length
        }
    }
}
