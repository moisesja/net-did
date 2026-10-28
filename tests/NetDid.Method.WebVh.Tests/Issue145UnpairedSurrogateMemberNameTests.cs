using System.Text;
using AwesomeAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Regression tests for issue #145: an unpaired UTF-16 surrogate escape in a JSON member NAME.
///
/// <c>JsonDocument.Parse</c> with <c>AllowDuplicateProperties = false</c> decodes every member
/// name to compare it, so a lone surrogate there throws <see cref="InvalidOperationException"/>
/// from <c>Parse</c> itself rather than <see cref="System.Text.Json.JsonException"/>. The
/// log-entry parse boundary caught only the latter, so the exception reached the resolver's
/// generic catch and a malformed fetched log resolved as <c>notFound</c> instead of
/// <c>invalidDidLog</c>, while Update/Deactivate leaked a raw <c>InvalidOperationException</c>
/// instead of their documented <see cref="FormatException"/>. A lone surrogate in a VALUE was
/// already mapped correctly and is kept here as a control.
/// </summary>
public class Issue145UnpairedSurrogateMemberNameTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    // ================================================================
    // Helpers
    // ================================================================

    private static (DidWebVhMethod Method, MockWebVhHttpClient HttpClient) CreateMethod()
    {
        var httpClient = new MockWebVhHttpClient();
        return (new DidWebVhMethod(httpClient), httpClient);
    }

    private async Task<(string Did, string Jsonl, ISigner Signer)> CreateLogAsync()
    {
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto);
        var (method, _) = CreateMethod();
        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });

        return (result.Did.Value, (string)result.Artifacts![DidWebVhArtifacts.DidJsonl], signer);
    }

    private static async Task<DidResolutionResult> ResolveLogAsync(string did, string log)
    {
        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(log));
        return await method.ResolveAsync(did);
    }

    /// <summary>Applies one textual substitution to the genesis line, asserting it applied.</summary>
    private static string DoctorGenesisLine(string jsonl, string find, string replace)
    {
        var line = jsonl.Split('\n')[0];
        line.Should().Contain(find, "the substitution anchor must exist in the genesis entry");
        var index = line.IndexOf(find, StringComparison.Ordinal);
        return line[..index] + replace + line[(index + find.Length)..];
    }

    // Member-name substitutions, at the entry root and at every nesting level the parser reaches.
    public static TheoryData<string, string> SurrogateMemberNames => new()
    {
        // Issue #145 table, row 1: a member name inside a proof object (proof array element).
        { "\"proofPurpose\":\"assertionMethod\"", "\"\\uD800\":1,\"proofPurpose\":\"assertionMethod\"" },
        // Issue #145 table, row 2: a member name directly inside state.
        { "\"state\":{", "\"state\":{\"\\uD800\":1," },
        // The log-entry root object.
        { "{\"versionId\"", "{\"\\uD800\":1,\"versionId\"" },
        // Inside parameters.
        { "\"parameters\":{", "\"parameters\":{\"\\uD800\":1," },
        // A deeper object nested inside state.
        { "\"state\":{", "\"state\":{\"x-ext\":{\"\\uD800\":1}," },
        // A lone LOW surrogate takes a different BCL decode path ("invalid", not "incomplete").
        { "\"state\":{", "\"state\":{\"\\uDC00\":1," },
    };

    #region Issue145_SurrogateMemberName_Resolution

    [Theory]
    [MemberData(nameof(SurrogateMemberNames))]
    public async Task Issue145_SurrogateMemberName_ParseThrowsFormatException(string find, string replace)
    {
        var (_, jsonl, _) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl, find, replace);

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));

        parse.Should().Throw<FormatException>()
            .WithInnerException<InvalidOperationException>();
    }

    [Theory]
    [MemberData(nameof(SurrogateMemberNames))]
    public async Task Issue145_SurrogateMemberName_ResolvesInvalidDidLog(string find, string replace)
    {
        var (did, jsonl, _) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl, find, replace);

        var result = await ResolveLogAsync(did, doctored);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog",
            "malformed content in a fetched log is an invalid DID log, not evidence that the DID is absent");
    }

    [Fact]
    public async Task Issue145_Control_SurrogateExtensionValue_ResolvesInvalidDidLog()
    {
        // Issue #145 table, row 3: the same escape in a VALUE position already mapped correctly.
        var (did, jsonl, _) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl,
            "\"proofPurpose\":\"assertionMethod\"",
            "\"x-ext\":\"\\uD800\",\"proofPurpose\":\"assertionMethod\"");

        var result = await ResolveLogAsync(did, doctored);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue145_Control_SurrogateModeledValue_ParseThrowsFormatException()
    {
        var (did, jsonl, _) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl,
            "\"proofPurpose\":\"assertionMethod\"", "\"proofPurpose\":\"\\uD800\"");

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().Throw<FormatException>();

        var result = await ResolveLogAsync(did, doctored);
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    #endregion

    #region Issue145_SurrogateMemberName_UpdateDeactivate

    [Fact]
    public async Task Issue145_Update_OnSurrogateMemberNameLog_ThrowsFormatException()
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl, "\"state\":{", "\"state\":{\"\\uD800\":1,");
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(doctored),
            SigningKey = signer
        });

        await act.Should().ThrowAsync<FormatException>(
            "Update reports malformed log content as FormatException, matching a malformed value");
    }

    [Fact]
    public async Task Issue145_Deactivate_OnSurrogateMemberNameLog_ThrowsFormatException()
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl,
            "\"proofPurpose\":\"assertionMethod\"", "\"\\uD800\":1,\"proofPurpose\":\"assertionMethod\"");
        var (method, _) = CreateMethod();

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(doctored),
            SigningKey = signer
        });

        await act.Should().ThrowAsync<FormatException>();
    }

    #endregion

    #region Issue145_WitnessFile_SurrogateMemberName (pins: this boundary already mapped it)

    [Theory]
    [InlineData("""[{"\uD800":1,"versionId":"1-QmA","proof":[]}]""")]
    [InlineData("""[{"versionId":"1-QmA","proof":[{"type":"DataIntegrityProof","\uD800":1}]}]""")]
    public void Issue145_WitnessFile_SurrogateMemberName_IsUnparseableWithBoundedReason(string json)
    {
        var parsed = WitnessValidator.ParseWitnessFile(Encoding.UTF8.GetBytes(json), out var parseError);

        parsed.Should().BeNull();
        parseError.Should().Be(nameof(InvalidOperationException),
            "the reason is a BCL type name, never hostile witness-file text");
    }

    [Fact]
    public async Task Issue145_Update_SurrogateMemberNameWitnessContent_ThrowsArgumentException()
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            CurrentWitnessContent = Encoding.UTF8.GetBytes(
                """[{"versionId":"1-QmA","proof":[{"\uD800":1}]}]""")
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    #endregion
}
