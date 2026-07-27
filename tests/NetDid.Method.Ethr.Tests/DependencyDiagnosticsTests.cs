using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Crypto;
using NetDid.Method.Ethr.Emulator;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// The write path wraps dependency failures in a library-owned carrier so an injected RPC
/// client cannot forge or suppress transaction evidence. That wrapper originally discarded the
/// dependency's detail entirely, which made the MOST COMMON real failure — an
/// <c>HttpClient</c> timeout, reported as <see cref="TaskCanceledException"/> — read as a
/// generic "a dependency canceled" at the top level, and silently re-typed it to its base
/// class so <c>catch (TaskCanceledException)</c> stopped matching.
///
/// These tests pin the resolution: dependency detail is surfaced, but sanitized and bounded,
/// and the evidence/anti-forgery guarantees are unchanged.
/// </summary>
public class DependencyDiagnosticsTests
{
    private const string Registry = "0x03d5003bf0e79c5f5223588f347eba39afbc3818";

    private sealed record Actor(KeyPairSigner Signer, string Address);

    private static Actor NewActor()
    {
        var pair = new DefaultKeyGenerator().Generate(KeyType.Secp256k1);
        return new Actor(
            new KeyPairSigner(pair, new DefaultCryptoProvider()),
            EthereumAddress.FromCompressedPublicKey(pair.PublicKey).ToLowerInvariant());
    }

    private static DidEthrMethod MethodFor(IEthereumRpcClient client)
        => new(new SingleNetworkRpcFactory("sepolia", client),
               [KnownNetworks.Sepolia with { RpcUrl = "http://emulated.local" }],
               new DefaultKeyGenerator());

    private static DidEthrServiceAttribute Svc(string type = "Hub")
        => new() { ServiceType = type, ServiceEndpoint = "https://hub.example" };

    /// <summary>Fails operation 2 with the supplied exception, after operation 1 confirms.</summary>
    private static async Task<Exception> FailSecondOperationAsync(
        EmulatedEthereumChain chain, Actor owner, Exception failure)
    {
        var sends = 0;
        var client = new FailingRpcClient(chain)
        {
            BeforeSend = () =>
            {
                if (++sends == 2) throw failure;
                return Task.CompletedTask;
            },
        };

        var act = () => MethodFor(client).UpdateAsync(
            $"did:ethr:sepolia:{owner.Address}",
            new DidEthrUpdateOptions
            {
                ControllerKey = owner.Signer,
                AddServices   = [Svc("A"), Svc("B")],
            });

        return (await act.Should().ThrowAsync<Exception>()).Which;
    }

    [Fact]
    public async Task HttpClientTimeout_KeepsItsTypeAndItsDetail()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        const string TimeoutMessage =
            "The request was canceled due to the configured HttpClient.Timeout of 30 seconds elapsing.";

        var thrown = await FailSecondOperationAsync(
            chain, owner, new TaskCanceledException(TimeoutMessage));

        // Type: a caller distinguishing a timeout must still be able to catch it.
        thrown.Should().BeOfType<TaskCanceledException>();

        // Detail: the operator learns what actually failed, at the top level.
        thrown.Message.Should().Contain("HttpClient.Timeout");

        // Evidence is unaffected by the diagnostics change.
        ((string[])thrown.Data[DidEthrMethod.LandedTransactionsKey]!).Should().ContainSingle();
        ((string[])thrown.Data[DidEthrMethod.InFlightTransactionsKey]!).Should().ContainSingle();
    }

    [Fact]
    public async Task SubclassedDependencyException_SurfacesTypeAndMessage()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        var thrown = await FailSecondOperationAsync(
            chain, owner, new CustomRpcException("upstream pool exhausted"));

        thrown.Message.Should().Contain(nameof(CustomRpcException))
            .And.Contain("upstream pool exhausted");
    }

    [Fact]
    public async Task HostileMessage_CannotInjectLogLines()
    {
        // CR/LF in a dependency message could forge entries in whatever consumes ours.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var injected = "boom\r\n2026-07-27 00:00:00 FATAL forged-entry: transfer approved";

        var thrown = await FailSecondOperationAsync(
            chain, owner, new CustomRpcException(injected));

        thrown.Message.Should().NotContain("\n").And.NotContain("\r");
        thrown.Message.Should().Contain("forged-entry",
            "the text is preserved for diagnosis — only its line structure is neutralised");
    }

    [Fact]
    public async Task HostileMessage_IsLengthBounded()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        var thrown = await FailSecondOperationAsync(
            chain, owner, new CustomRpcException(new string('x', 100_000)));

        thrown.Message.Length.Should().BeLessThan(2_000,
            "an oversized dependency message must not bloat the caller's logs");
        thrown.Message.Should().Contain("…");
    }

    [Fact]
    public async Task HostileThrowingMessageAccessor_DoesNotDefeatTheCarrier()
    {
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();

        var thrown = await FailSecondOperationAsync(chain, owner, new ThrowingMessageException());

        thrown.Message.Should().Contain("message unavailable");
        ((string[])thrown.Data[DidEthrMethod.LandedTransactionsKey]!).Should().ContainSingle(
            "evidence must survive a dependency whose Message accessor throws");
    }

    [Fact]
    public async Task ForgedEvidenceOnADependencyException_IsStillNotTrusted()
    {
        // Surfacing the dependency's MESSAGE must not soften the evidence boundary.
        var chain = new EmulatedEthereumChain(Registry);
        var owner = NewActor();
        var forged = new CustomRpcException("looks legitimate");
        forged.Data[DidEthrMethod.LandedTransactionsKey] = new[] { "0x" + new string('f', 64) };

        var thrown = await FailSecondOperationAsync(chain, owner, forged);

        ((string[])thrown.Data[DidEthrMethod.LandedTransactionsKey]!)
            .Should().ContainSingle().Which.Should().NotBe("0x" + new string('f', 64));
    }

    private sealed class CustomRpcException(string message) : EthereumInteractionException(message);

    private sealed class ThrowingMessageException : Exception
    {
        public override string Message => throw new InvalidOperationException("hostile Message");
    }

    private sealed class FailingRpcClient(EmulatedEthereumChain inner) : IEthereumRpcClient
    {
        public Func<Task>? BeforeSend { get; init; }

        public Task<string> CallAsync(string to, string data, CancellationToken ct = default)
            => inner.CallAsync(to, data, ct);
        public Task<IReadOnlyList<EthereumLogEntry>> GetLogsAsync(EthereumLogFilter f, CancellationToken ct = default)
            => inner.GetLogsAsync(f, ct);
        public Task<ulong> GetBlockNumberAsync(CancellationToken ct = default) => inner.GetBlockNumberAsync(ct);
        public Task<ulong> GetChainIdAsync(CancellationToken ct = default) => inner.GetChainIdAsync(ct);
        public Task<ulong> GetBlockTimestampAsync(ulong b, CancellationToken ct = default)
            => inner.GetBlockTimestampAsync(b, ct);
        public Task<ulong> GetTransactionCountAsync(string a, CancellationToken ct = default)
            => inner.GetTransactionCountAsync(a, ct);
        public Task<ulong> GetGasPriceAsync(CancellationToken ct = default) => inner.GetGasPriceAsync(ct);
        public Task<ulong> EstimateGasAsync(string f, string? t, string d, CancellationToken ct = default)
            => inner.EstimateGasAsync(f, t, d, ct);

        public async Task<string> SendRawTransactionAsync(byte[] raw, CancellationToken ct = default)
        {
            if (BeforeSend is not null) await BeforeSend();
            return await inner.SendRawTransactionAsync(raw, ct);
        }

        public Task<EthereumTransactionReceipt?> GetTransactionReceiptAsync(
            string hash, CancellationToken ct = default)
            => inner.GetTransactionReceiptAsync(hash, ct);
    }
}
