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

        // Only the numeric code is surfaced — the node-authored message string is
        // never read (PR #122 round 3: decoding it is an unbounded allocation and a
        // log-injection channel, even for an honest-looking value).
        var assertion = await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*RPC error*code -32000*");
        assertion.Which.Message.Should().NotContain("boom");
    }

    [Fact]
    public async Task Issue116_OversizedRpcErrorMessage_NeverMaterialized()
    {
        // PR #122 review round 3, finding 2: TryGetValue<string> materialized the full
        // attacker string before truncation (~16 MB message → ~32 MB LOH churn). The
        // diagnostic now never reads the message member at all — only the numeric code
        // — so no attacker content of any size can reach the exception or logs.
        var huge = new string('&', 1_000_000);
        var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\""
                   + huge + "\",\"data\":{\"nested\":\"" + huge + "\"}}}";
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(body));

        var assertion = await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>();

        assertion.Which.Message.Length.Should().BeLessThan(200,
            "the diagnostic carries only the bounded numeric code");
        assertion.Which.Message.Should().Contain("code -32000");
        assertion.Which.Message.Should().NotContain("&");
    }

    [Fact]
    public async Task Issue116_LogForgingRpcErrorMessage_NoHostileContentInDiagnostic()
    {
        // CR/LF (log-line forging), ANSI ESC, U+2028 (JS line separator), and an
        // astral pair positioned where a naive truncation would split it - none may
        // reach the exception/log text. (A lone surrogate cannot even be delivered:
        // System.Text.Json rejects it at parse.) The fixed diagnostic guarantees this
        // structurally; the test pins the property. All hostile bytes arrive as JSON
        // \u escapes so this source file stays free of literal control characters.
        const string marker = "FORGED-WARN-admin";
        var hostile = "ok\\r\\n" + marker + " \\u001b[31m\\u2028NEXT\\ud83d\\ude00";
        var body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\""
                   + hostile + "\"}}";
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(body));

        var assertion = await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>();

        var text = assertion.Which.Message;
        text.Should().NotContain(marker);
        text.Should().NotContainAny("\r", "\n", "\u001b", "\u2028");
        text.Should().NotContain("NEXT");
        foreach (var ch in text)
            char.IsSurrogate(ch).Should().BeFalse("the diagnostic must be valid, plain UTF-16");
    }

    [Fact]
    public async Task Issue116_NonObjectRpcError_YieldsFixedDiagnostic()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":\"just a string\"}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*RPC error*non-object error member*");
    }

    [Fact]
    public async Task Issue116_DuplicateMembersInsideErrorObject_MappedAtTrustBoundary()
    {
        // Lazy JsonObject materialization throws ArgumentException on duplicate keys;
        // PR #122 round 3: that must surface as the boundary's EthereumInteractionException,
        // never a raw JSON-layer exception.
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"code\":-32001,\"message\":\"x\"}}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*RPC error*malformed error member*");
    }

    [Fact]
    public async Task Issue116_DuplicateEnvelopeMembers_MappedAtTrustBoundary()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-1},\"error\":{\"code\":-2}}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*invalid or duplicate envelope members*");
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

    [Theory]
    [InlineData("[]")]
    [InlineData("42")]
    [InlineData("\"not-an-object\"")]
    public async Task Pr104Round2_NonObjectRpcEnvelope_ThrowsEthereumInteractionException(
        string json)
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(json));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*object*");
    }

    [Theory]
    [InlineData("42")]
    [InlineData("{}")]
    [InlineData("[]")]
    public async Task Pr104Round2_GetChainId_InvalidResultShape_ThrowsEthereumInteractionException(
        string resultJson)
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{resultJson}}}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*eth_chainId*");
    }

    [Fact]
    public async Task Pr104Round2_Call_InvalidResultShape_ThrowsEthereumInteractionException()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":42}"));

        await client.Invoking(c => c.CallAsync("0x0000000000000000000000000000000000000000", "0x"))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*eth_call*");
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{}")]
    [InlineData("{\"timestamp\":42}")]
    public async Task Pr104Round2_GetBlockTimestamp_InvalidResultShape_ThrowsEthereumInteractionException(
        string resultJson)
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{resultJson}}}"));

        await client.Invoking(c => c.GetBlockTimestampAsync(1))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*eth_getBlockByNumber*");
    }

    [Theory]
    [InlineData("0X1")]
    [InlineData("0xA")]
    [InlineData("0x01")]
    [InlineData("0x")]
    public async Task Pr104Round2_GetChainId_NonCanonicalQuantity_ThrowsEthereumInteractionException(
        string quantity)
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"{quantity}\"}}"));

        await client.Invoking(c => c.GetChainIdAsync())
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*eth_chainId*");
    }

    [Theory]
    [InlineData("")]
    [InlineData(",\"logIndex\":null")]
    [InlineData(",\"logIndex\":\"not-hex\"")]
    [InlineData(",\"logIndex\":\"0x\"")]
    [InlineData(",\"logIndex\":\"1\"")]
    [InlineData(",\"logIndex\":\"0x00\"")]
    [InlineData(",\"logIndex\":\"0X1\"")]
    [InlineData(",\"logIndex\":\"0xA\"")]
    public async Task Pr104Round2_GetLogs_InvalidLogIndex_ThrowsEthereumInteractionException(
        string logIndexProperty)
    {
        var json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[{"
            + "\"address\":\"0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B\","
            + "\"topics\":[\"0x01\",\"0x02\"],\"data\":\"0x\","
            + "\"blockNumber\":\"0x1\""
            + logIndexProperty
            + ",\"removed\":false"
            + "}]}";
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(json));

        await client.Invoking(c => c.GetLogsAsync(LogFilter()))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*logIndex*");
    }

    [Fact]
    public async Task Pr104Round2_GetLogs_NullArrayEntry_ThrowsEthereumInteractionException()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[null]}"));

        await client.Invoking(c => c.GetLogsAsync(LogFilter()))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*null*");
    }

    [Theory]
    [InlineData(",\"removed\":null")]
    [InlineData(",\"removed\":\"false\"")]
    [InlineData(",\"removed\":true")]
    public async Task Pr104Round2_GetLogs_InvalidOrRemovedFlag_ThrowsEthereumInteractionException(
        string removedProperty)
    {
        var json = LogResponse(
            blockNumber: "0x1",
            logIndex: "0x0",
            extraProperty: removedProperty);
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(json));

        await client.Invoking(c => c.GetLogsAsync(LogFilter()))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*removed*");
    }

    [Fact]
    public async Task Pr104Review_GetLogs_OmittedRemovedFlag_ReturnsCanonicalLog()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            LogResponse("0x1", "0x0", "")));

        var logs = await client.GetLogsAsync(LogFilter());

        logs.Should().ContainSingle();
        logs[0].BlockNumber.Should().Be("0x1");
        logs[0].LogIndex.Should().Be(0);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("0x01")]
    [InlineData("0x")]
    [InlineData("0X1")]
    [InlineData("0xA")]
    public async Task Pr104Round2_GetLogs_NonCanonicalBlockNumber_ThrowsEthereumInteractionException(
        string blockNumber)
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            LogResponse(blockNumber, "0x0", ",\"removed\":false")));

        await client.Invoking(c => c.GetLogsAsync(LogFilter()))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*blockNumber*");
    }

    [Fact]
    public async Task Pr104Round2_GetLogs_CanonicalMetadata_ReturnsLog()
    {
        var client = ClientReturning(HttpStatusCode.OK, new StringContent(
            LogResponse("0x1", "0x0", ",\"removed\":false")));

        var logs = await client.GetLogsAsync(LogFilter());

        logs.Should().ContainSingle();
        logs[0].BlockNumber.Should().Be("0x1");
        logs[0].LogIndex.Should().Be(0);
    }

    // ── Stubs ─────────────────────────────────────────────────────────────────────

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(responder(request));
    }

    private static EthereumLogFilter LogFilter() => new()
    {
        Address = "0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B",
        FromBlock = 1,
        ToBlock = 1,
        Topics = [],
    };

    private static string LogResponse(
        string blockNumber, string logIndex, string extraProperty)
        => "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":[{"
            + "\"address\":\"0xdCa7EF03e98e0DC2B855bE647C39ABe984fcF21B\","
            + "\"topics\":[\"0x01\",\"0x02\"],\"data\":\"0x\","
            + $"\"blockNumber\":\"{blockNumber}\",\"logIndex\":\"{logIndex}\""
            + extraProperty
            + "}]}";

    /// <summary>Streams a fixed number of bytes with no Content-Length header.</summary>
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
