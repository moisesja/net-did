using System.Net;
using System.Text;
using FluentAssertions;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Regression tests for issue #51: DefaultWebVhHttpClient must bound the
/// number of bytes it reads from a did:webvh host so that a hostile or
/// misconfigured server cannot push hundreds of MB into the resolver.
/// </summary>
public class DefaultWebVhHttpClientTests
{
    private static readonly Uri LogUrl = new("https://example.com/.well-known/did.jsonl");
    private static readonly Uri WitnessUrl = new("https://example.com/.well-known/did-witness.json");

    private static DefaultWebVhHttpClient BuildClient(
        HttpMessageHandler handler, WebVhHttpClientOptions? options = null)
        => new(new HttpClient(handler), options);

    // --- log: happy paths ---

    [Fact]
    public async Task FetchDidLog_SmallResponse_ReturnsBytes()
    {
        var body = Encoding.UTF8.GetBytes("{\"versionId\":\"1-z\"}\n");
        var handler = new StubHttpHandler(body, declaredContentLength: body.Length);
        var client = BuildClient(handler);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().Equal(body);
    }

    [Fact]
    public async Task FetchDidLog_NoContentLength_SmallBody_ReturnsBytes()
    {
        var body = Encoding.UTF8.GetBytes("{\"versionId\":\"1-z\"}");
        var handler = new StubHttpHandler(body, declaredContentLength: null);
        var client = BuildClient(handler);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().Equal(body);
    }

    // --- log: enforcement ---

    [Fact]
    public async Task FetchDidLog_DeclaredContentLengthAboveLimit_ReturnsNull()
    {
        // Declared length exceeds limit — the body must not even be read.
        var options = new WebVhHttpClientOptions { MaxDidLogBytes = 1024 };
        var handler = new StubHttpHandler(new byte[10], declaredContentLength: 99999);
        var client = BuildClient(handler, options);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchDidLog_BodyExceedsLimitWithNoContentLength_ReturnsNull()
    {
        // Hostile server omits Content-Length and slow-drips an oversized body.
        // The streaming reader must abort once the limit is crossed.
        var options = new WebVhHttpClientOptions { MaxDidLogBytes = 1024 };
        var oversized = new byte[options.MaxDidLogBytes + 8192];
        var handler = new StubHttpHandler(oversized, declaredContentLength: null);
        var client = BuildClient(handler, options);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchDidLog_ExactlyAtLimit_ReturnsBytes()
    {
        var options = new WebVhHttpClientOptions { MaxDidLogBytes = 1024 };
        var body = new byte[options.MaxDidLogBytes];
        var handler = new StubHttpHandler(body, declaredContentLength: body.Length);
        var client = BuildClient(handler, options);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().NotBeNull();
        result!.Length.Should().Be((int)options.MaxDidLogBytes);
    }

    // --- witness: enforcement ---

    [Fact]
    public async Task FetchWitnessFile_DeclaredContentLengthAboveLimit_ReturnsNull()
    {
        var options = new WebVhHttpClientOptions { MaxWitnessFileBytes = 512 };
        var handler = new StubHttpHandler(new byte[10], declaredContentLength: 99999);
        var client = BuildClient(handler, options);

        var result = await client.FetchWitnessFileAsync(WitnessUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchWitnessFile_BodyExceedsLimitWithNoContentLength_ReturnsNull()
    {
        var options = new WebVhHttpClientOptions { MaxWitnessFileBytes = 512 };
        var oversized = new byte[options.MaxWitnessFileBytes + 8192];
        var handler = new StubHttpHandler(oversized, declaredContentLength: null);
        var client = BuildClient(handler, options);

        var result = await client.FetchWitnessFileAsync(WitnessUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchWitnessFile_SmallResponse_ReturnsBytes()
    {
        var body = Encoding.UTF8.GetBytes("[]");
        var handler = new StubHttpHandler(body, declaredContentLength: body.Length);
        var client = BuildClient(handler);

        var result = await client.FetchWitnessFileAsync(WitnessUrl);

        result.Should().Equal(body);
    }

    // --- error paths ---

    [Fact]
    public async Task FetchDidLog_NonSuccessStatus_ReturnsNull()
    {
        var handler = new StubHttpHandler(Array.Empty<byte>(),
            declaredContentLength: 0, statusCode: HttpStatusCode.NotFound);
        var client = BuildClient(handler);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchDidLog_HttpRequestException_ReturnsNull()
    {
        var handler = new ThrowingHttpHandler();
        var client = BuildClient(handler);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchDidLog_DefaultLimits_AreFiveAndOneMiB()
    {
        var defaults = new WebVhHttpClientOptions();
        defaults.MaxDidLogBytes.Should().Be(5L * 1024 * 1024);
        defaults.MaxWitnessFileBytes.Should().Be(1L * 1024 * 1024);
    }

    // --- helpers ---

    /// <summary>
    /// Returns a fixed body. Can optionally suppress the auto-computed
    /// Content-Length header so the streaming path is exercised.
    /// </summary>
    private sealed class StubHttpHandler : HttpMessageHandler
    {
        private readonly byte[] _body;
        private readonly long? _declaredContentLength;
        private readonly HttpStatusCode _statusCode;

        public StubHttpHandler(byte[] body, long? declaredContentLength,
            HttpStatusCode statusCode = HttpStatusCode.OK)
        {
            _body = body;
            _declaredContentLength = declaredContentLength;
            _statusCode = statusCode;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpContent content;
            if (_declaredContentLength is null)
            {
                // StreamContent doesn't auto-set Content-Length, so the client must rely on streaming.
                content = new StreamContent(new MemoryStream(_body));
            }
            else
            {
                content = new ByteArrayContent(_body);
                content.Headers.ContentLength = _declaredContentLength;
            }

            return Task.FromResult(new HttpResponseMessage(_statusCode) { Content = content });
        }
    }

    private sealed class ThrowingHttpHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => throw new HttpRequestException("simulated network failure");
    }
}
