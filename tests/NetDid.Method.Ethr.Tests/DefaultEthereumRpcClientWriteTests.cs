using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using NetDid.Core.Exceptions;
using NetDid.Method.Ethr.Rpc;
using Xunit;

namespace NetDid.Method.Ethr.Tests;

/// <summary>
/// Trust-boundary tests for the JSON-RPC WRITE surface (issue #107). The node stays
/// untrusted on the write path: a malformed tx-hash echo, a receipt for the wrong
/// transaction, a non-Boolean-ish status, or a garbled contractAddress must surface as
/// <see cref="EthereumInteractionException"/> — never silently succeed.
/// </summary>
public class DefaultEthereumRpcClientWriteTests
{
    private const string TxHash =
        "0x" + "ab12" + "00000000000000000000000000000000000000000000000000000000ab12";

    private static (DefaultEthereumRpcClient Client, List<JsonObject> Requests) ClientReturning(
        params string[] resultJsonBodies)
    {
        var requests = new List<JsonObject>();
        var queue = new Queue<string>(resultJsonBodies);
        var handler = new StubHandler(request =>
        {
            var body = request.Content!.ReadAsStringAsync().GetAwaiter().GetResult();
            requests.Add(JsonNode.Parse(body)!.AsObject());
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(queue.Dequeue(), Encoding.UTF8, "application/json"),
            };
        });
        var http = new HttpClient(handler) { BaseAddress = new Uri("http://rpc.local") };
        return (new DefaultEthereumRpcClient(http), requests);
    }

    private static string Result(string resultJson)
        => $"{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{resultJson}}}";

    // ── eth_sendRawTransaction ───────────────────────────────────────────────

    [Fact]
    public async Task SendRawTransaction_HexEncodesAndReturnsHash()
    {
        var (client, requests) = ClientReturning(Result($"\"{TxHash}\""));

        var hash = await client.SendRawTransactionAsync([0xf8, 0x6c, 0x01]);

        hash.Should().Be(TxHash);
        requests[0]["method"]!.GetValue<string>().Should().Be("eth_sendRawTransaction");
        requests[0]["params"]![0]!.GetValue<string>().Should().Be("0xf86c01");
    }

    [Fact]
    public async Task SendRawTransaction_EmptyPayload_ThrowsArgumentException()
    {
        var (client, _) = ClientReturning();
        await client.Invoking(c => c.SendRawTransactionAsync([]))
            .Should().ThrowAsync<ArgumentException>().WithParameterName("signedTransaction");
    }

    [Theory]
    [InlineData("\"0x1234\"")]                       // too short
    [InlineData("\"nothex\"")]                       // no 0x
    [InlineData("\"0xAB12" + "00000000000000000000000000000000000000000000000000000000ab12\"")] // uppercase
    [InlineData("42")]                               // not a string
    public async Task SendRawTransaction_MalformedHashEcho_Throws(string resultJson)
    {
        var (client, _) = ClientReturning(Result(resultJson));
        await client.Invoking(c => c.SendRawTransactionAsync([0x01]))
            .Should().ThrowAsync<EthereumInteractionException>();
    }

    // ── eth_getTransactionCount / eth_gasPrice ───────────────────────────────

    [Fact]
    public async Task GetTransactionCount_UsesPendingTag_AndParsesQuantity()
    {
        var (client, requests) = ClientReturning(Result("\"0x1a\""));

        var nonce = await client.GetTransactionCountAsync("0x" + new string('1', 40));

        nonce.Should().Be(26);
        requests[0]["params"]![1]!.GetValue<string>().Should().Be("pending");
    }

    [Theory]
    [InlineData("\"0x01\"")]   // leading zero — non-canonical
    [InlineData("\"26\"")]     // no 0x
    [InlineData("\"0x\"")]     // empty quantity
    public async Task GetTransactionCount_NonCanonicalQuantity_Throws(string resultJson)
    {
        var (client, _) = ClientReturning(Result(resultJson));
        await client.Invoking(c => c.GetTransactionCountAsync("0x" + new string('1', 40)))
            .Should().ThrowAsync<EthereumInteractionException>();
    }

    [Fact]
    public async Task GetGasPrice_ParsesQuantity()
    {
        var (client, _) = ClientReturning(Result("\"0x4a817c800\""));
        (await client.GetGasPriceAsync()).Should().Be(20_000_000_000);
    }

    // ── eth_getTransactionReceipt ────────────────────────────────────────────

    private static string ReceiptJson(
        string? status = "\"0x1\"", string? blockNumber = "\"0x64\"",
        string? transactionHash = $"\"{TxHash}\"", string? contractAddress = null)
    {
        var fields = new List<string>();
        if (status is not null) fields.Add($"\"status\":{status}");
        if (blockNumber is not null) fields.Add($"\"blockNumber\":{blockNumber}");
        if (transactionHash is not null) fields.Add($"\"transactionHash\":{transactionHash}");
        if (contractAddress is not null) fields.Add($"\"contractAddress\":{contractAddress}");
        return "{" + string.Join(",", fields) + "}";
    }

    [Fact]
    public async Task GetReceipt_NullResult_MeansPending_ReturnsNull()
    {
        var (client, _) = ClientReturning(Result("null"));
        (await client.GetTransactionReceiptAsync(TxHash)).Should().BeNull();
    }

    [Fact]
    public async Task GetReceipt_SuccessStatus_MapsToSucceeded()
    {
        var (client, _) = ClientReturning(Result(ReceiptJson()));

        var receipt = await client.GetTransactionReceiptAsync(TxHash);

        receipt.Should().NotBeNull();
        receipt!.Succeeded.Should().BeTrue();
        receipt.BlockNumber.Should().Be(100);
        receipt.TransactionHash.Should().Be(TxHash);
        receipt.ContractAddress.Should().BeNull();
    }

    [Fact]
    public async Task GetReceipt_RevertStatus_MapsToFailed()
    {
        var (client, _) = ClientReturning(Result(ReceiptJson(status: "\"0x0\"")));
        (await client.GetTransactionReceiptAsync(TxHash))!.Succeeded.Should().BeFalse();
    }

    [Fact]
    public async Task GetReceipt_ContractAddress_IsReturned()
    {
        var deployed = "0x" + new string('a', 40);
        var (client, _) = ClientReturning(
            Result(ReceiptJson(contractAddress: $"\"{deployed}\"")));

        (await client.GetTransactionReceiptAsync(TxHash))!
            .ContractAddress.Should().Be(deployed);
    }

    [Theory]
    [InlineData("\"0x2\"")]     // unknown status
    [InlineData("\"success\"")] // non-quantity status
    [InlineData("1")]           // numeric status
    public async Task GetReceipt_UnexpectedStatus_Throws(string status)
    {
        var (client, _) = ClientReturning(Result(ReceiptJson(status: status)));
        await client.Invoking(c => c.GetTransactionReceiptAsync(TxHash))
            .Should().ThrowAsync<EthereumInteractionException>();
    }

    [Fact]
    public async Task GetReceipt_MissingStatus_Throws()
    {
        var (client, _) = ClientReturning(Result(ReceiptJson(status: null)));
        await client.Invoking(c => c.GetTransactionReceiptAsync(TxHash))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*status*");
    }

    [Fact]
    public async Task GetReceipt_ForWrongTransaction_Throws()
    {
        // A hostile or confused node answering with a DIFFERENT transaction's receipt
        // must not be trusted as confirmation of ours.
        var other = "0x" + new string('c', 64);
        var (client, _) = ClientReturning(
            Result(ReceiptJson(transactionHash: $"\"{other}\"")));

        await client.Invoking(c => c.GetTransactionReceiptAsync(TxHash))
            .Should().ThrowAsync<EthereumInteractionException>()
            .WithMessage("*instead of the requested*");
    }

    [Theory]
    [InlineData("\"0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD00\"")] // wrong length
    [InlineData("\"" + "0x" + "ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD" + "\"")] // uppercase
    [InlineData("\"deadbeef\"")]                                     // no 0x
    public async Task GetReceipt_MalformedContractAddress_Throws(string contractAddress)
    {
        var (client, _) = ClientReturning(
            Result(ReceiptJson(contractAddress: contractAddress)));
        await client.Invoking(c => c.GetTransactionReceiptAsync(TxHash))
            .Should().ThrowAsync<EthereumInteractionException>();
    }

    // ── eth_estimateGas ──────────────────────────────────────────────────────

    [Fact]
    public async Task EstimateGas_WithRecipient_SendsFromToData()
    {
        var (client, requests) = ClientReturning(Result("\"0x5208\""));
        var from = "0x" + new string('1', 40);
        var to = "0x" + new string('2', 40);

        var gas = await client.EstimateGasAsync(from, to, "0xdeadbeef");

        gas.Should().Be(21_000);
        var call = requests[0]["params"]![0]!.AsObject();
        call["from"]!.GetValue<string>().Should().Be(from);
        call["to"]!.GetValue<string>().Should().Be(to);
        call["data"]!.GetValue<string>().Should().Be("0xdeadbeef");
    }

    [Fact]
    public async Task EstimateGas_ContractCreation_OmitsTo()
    {
        var (client, requests) = ClientReturning(Result("\"0x186a0\""));

        await client.EstimateGasAsync("0x" + new string('1', 40), to: null, "0x6080");

        var call = requests[0]["params"]![0]!.AsObject();
        call.ContainsKey("to").Should().BeFalse();
    }

    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
            => Task.FromResult(responder(request));
    }
}
