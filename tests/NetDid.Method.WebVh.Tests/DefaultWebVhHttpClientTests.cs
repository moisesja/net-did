using System.Net;
using System.Reflection;
using System.Text;
using FluentAssertions;
using NetDid.Method.WebVh;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Security regression tests for bounded response reads and SSRF-safe request
/// handling by <see cref="DefaultWebVhHttpClient"/>.
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
    public async Task FetchDidLog_OneByteOverLimitWithNoContentLength_ReturnsNull()
    {
        // Pins the exact streaming boundary: maxBytes is accepted, maxBytes + 1
        // is not, even when the server hides the size by omitting Content-Length.
        var options = new WebVhHttpClientOptions { MaxDidLogBytes = 1024 };
        var oversized = new byte[options.MaxDidLogBytes + 1];
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
    public async Task FetchDidLog_NonHttpsUrl_IsRejectedBeforeCallerControlledHandler()
    {
        var handler = new RecordingHandler();
        var client = BuildClient(handler);

        var result = await client.FetchDidLogAsync(
            new Uri("http://example.com/.well-known/did.jsonl"));

        result.Should().BeNull();
        handler.SendCount.Should().Be(0);
    }

    [Theory]
    [InlineData("https://localhost/.well-known/did.jsonl")]
    [InlineData("https://127.0.0.1/.well-known/did.jsonl")]
    [InlineData("https://10.0.0.1/.well-known/did.jsonl")]
    [InlineData("https://169.254.169.254/.well-known/did.jsonl")]
    [InlineData("https://[::1]/.well-known/did.jsonl")]
    [InlineData("https://localhost。/.well-known/did.jsonl")]
    [InlineData("https://１２７。０。０。１/.well-known/did.jsonl")]
    public async Task FetchDidLog_NonPublicLiteral_IsRejectedBeforeCallerControlledHandler(
        string url)
    {
        var handler = new RecordingHandler();
        var client = BuildClient(handler);

        var result = await client.FetchDidLogAsync(new Uri(url));

        result.Should().BeNull();
        handler.SendCount.Should().Be(0);
    }

    [Fact]
    public async Task FetchDidLog_AlreadyCancelledUnsafeRequest_PropagatesWithoutDispatch()
    {
        var handler = new RecordingHandler();
        var client = BuildClient(handler);
        using var callerCts = new CancellationTokenSource();
        callerCts.Cancel();

        var act = () => client.FetchDidLogAsync(
            new Uri("http://localhost/.well-known/did.jsonl"), callerCts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
        handler.SendCount.Should().Be(0);
    }

    [Fact]
    public void CreateSecurePrimaryHandler_DisablesRedirectsAndProxies()
    {
        using var handler = DefaultWebVhHttpClient.CreateSecurePrimaryHandler();

        handler.AllowAutoRedirect.Should().BeFalse();
        handler.UseProxy.Should().BeFalse();
        handler.ConnectCallback.Should().NotBeNull();
    }

    [Fact]
    public async Task FetchDidLog_DefaultLimits_AreFiveAndOneMiB()
    {
        var defaults = new WebVhHttpClientOptions();
        defaults.MaxDidLogBytes.Should().Be(5L * 1024 * 1024);
        defaults.MaxWitnessFileBytes.Should().Be(1L * 1024 * 1024);
    }

    // --- timeout enforcement (issue #80) ---

    [Fact]
    public void WebVhHttpClientOptions_DefaultTimeout_IsThirtySeconds()
    {
        new WebVhHttpClientOptions().Timeout.Should().Be(TimeSpan.FromSeconds(30));
    }

    [Theory]
    [InlineData(0)]     // zero would silently cancel every fetch
    [InlineData(-5)]    // negative would throw from CancelAfter at fetch time
    public void WebVhHttpClientOptions_NonPositiveTimeout_ThrowsAtConstruction(int seconds)
    {
        var act = () => new WebVhHttpClientOptions { Timeout = TimeSpan.FromSeconds(seconds) };

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WebVhHttpClientOptions_TimeoutBeyondCancelAfterRange_ThrowsAtConstruction()
    {
        var act = () => new WebVhHttpClientOptions
        {
            Timeout = TimeSpan.FromMilliseconds((long)int.MaxValue + 1)
        };

        act.Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void WebVhHttpClientOptions_InfiniteTimeout_IsAccepted()
    {
        var options = new WebVhHttpClientOptions
        {
            Timeout = System.Threading.Timeout.InfiniteTimeSpan
        };

        options.Timeout.Should().Be(System.Threading.Timeout.InfiniteTimeSpan);
    }

    [Fact]
    public void OwnedHttpClient_NeutralizesHttpClientTimeout()
    {
        // HttpClient.Timeout (100s framework default) enforces itself
        // independently of the per-fetch token, so it would silently cap any
        // options.Timeout above 100s. For the client the library constructs
        // itself, options.Timeout must be the sole time authority. Reflection,
        // because the owned client is deliberately not exposed.
        using var client = new DefaultWebVhHttpClient();

        var http = (HttpClient)typeof(DefaultWebVhHttpClient)
            .GetField("_httpClient", BindingFlags.NonPublic | BindingFlags.Instance)!
            .GetValue(client)!;

        http.Timeout.Should().Be(System.Threading.Timeout.InfiniteTimeSpan);
    }

    [Fact]
    public void InjectedHttpClient_TimeoutIsLeftUntouched()
    {
        // A caller-injected client keeps its own Timeout as an independent
        // bound — the library must not mutate configuration it does not own.
        using var injected = new HttpClient(new StubHttpHandler(new byte[0], 0))
        {
            Timeout = TimeSpan.FromSeconds(7)
        };

        using var client = new DefaultWebVhHttpClient(injected);

        injected.Timeout.Should().Be(TimeSpan.FromSeconds(7));
    }

    [Fact]
    public async Task FetchDidLog_HostWithholdsHeadersBeyondTimeout_ReturnsNull()
    {
        // Slowloris-style host: handshake succeeds, response headers never arrive.
        var options = new WebVhHttpClientOptions { Timeout = TimeSpan.FromMilliseconds(100) };
        var client = BuildClient(new NeverRespondingHttpHandler(), options);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchDidLog_HostStallsBodyBeyondTimeout_ReturnsNull()
    {
        // Headers arrive promptly but the body never does. HttpClient.Timeout
        // does not cover this phase under ResponseHeadersRead, so it is the
        // per-fetch timeout that must abort the read.
        var options = new WebVhHttpClientOptions { Timeout = TimeSpan.FromMilliseconds(100) };
        var handler = new StubHttpHandler(new byte[0], declaredContentLength: null)
        {
            BodyStreamOverride = new StallingStream()
        };
        var client = BuildClient(handler, options);

        var result = await client.FetchDidLogAsync(LogUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchWitnessFile_HostWithholdsHeadersBeyondTimeout_ReturnsNull()
    {
        var options = new WebVhHttpClientOptions { Timeout = TimeSpan.FromMilliseconds(100) };
        var client = BuildClient(new NeverRespondingHttpHandler(), options);

        var result = await client.FetchWitnessFileAsync(WitnessUrl);

        result.Should().BeNull();
    }

    [Fact]
    public async Task FetchDidLog_CallerCancellation_PropagatesInsteadOfReturningNull()
    {
        // The per-fetch timeout must not mask genuine cooperative cancellation
        // (the #81 contract): a cancelled caller token surfaces as
        // OperationCanceledException, never as a null "not found" fetch.
        var options = new WebVhHttpClientOptions { Timeout = TimeSpan.FromSeconds(10) };
        var client = BuildClient(new NeverRespondingHttpHandler(), options);
        using var callerCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var act = () => client.FetchDidLogAsync(LogUrl, callerCts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
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

        /// <summary>When set, serves this stream as the body instead of the byte array.</summary>
        public Stream? BodyStreamOverride { get; init; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpContent content;
            if (_declaredContentLength is null)
            {
                // StreamContent doesn't auto-set Content-Length, so the client must rely on streaming.
                content = new StreamContent(BodyStreamOverride ?? new MemoryStream(_body));
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

    /// <summary>
    /// Simulates a host that completes the handshake but never sends response
    /// headers: completes only via the request's cancellation token.
    /// </summary>
    private sealed class NeverRespondingHttpHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, cancellationToken);
            throw new InvalidOperationException("unreachable");
        }
    }

    /// <summary>
    /// A non-seekable body stream that never yields data: reads block until
    /// the read's cancellation token fires.
    /// </summary>
    private sealed class StallingStream : Stream
    {
        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public int SendCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            SendCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent([])
            });
        }
    }
}
