using System.Text;
using AwesomeAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Core.Serialization;
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

    #region Issue145_UndecodedSurrogateValue (adversarial review: values the model drops)

    // A verification method whose publicKeyJwk carries an unknown member. The typed model and its
    // fingerprint never read that member, so before the fix its lone surrogate was first decoded
    // only when the raw state was re-emitted for hashing, outside the parse boundary (notFound).
    private static string JwkVerificationMethod(string did, string extensionJson) =>
        "{\"id\":\"" + did + "#jwk\",\"type\":\"JsonWebKey2020\",\"controller\":\"" + did + "\"," +
        "\"publicKeyJwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\"," +
        "\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"x-ext\":" + extensionJson + "}}";

    public static TheoryData<string> UndecodedSurrogateValues => new()
    {
        """{"a":"\uD800"}""",
        """["\uD800"]""",
        """{"a":[{"b":"\uDC00"}]}""",
    };

    private static string WithJwkVerificationMethod(string line, string did, string extensionJson)
    {
        const string anchor = "\"verificationMethod\":[";
        line.Should().Contain(anchor);
        var index = line.IndexOf(anchor, StringComparison.Ordinal) + anchor.Length;
        return line[..index] + JwkVerificationMethod(did, extensionJson) + "," + line[index..];
    }

    [Theory]
    [MemberData(nameof(UndecodedSurrogateValues))]
    public async Task Issue145_UndecodedSurrogateValue_GenesisLine_ResolvesInvalidDidLog(string extensionJson)
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var doctored = WithJwkVerificationMethod(jsonl.Split('\n')[0], did, extensionJson);

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().Throw<FormatException>().WithInnerException<InvalidOperationException>();

        var result = await ResolveLogAsync(did, doctored);
        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");

        var (method, _) = CreateMethod();
        var update = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(doctored),
            SigningKey = signer
        });
        await update.Should().ThrowAsync<FormatException>();
    }

    [Fact]
    public async Task Issue145_UndecodedSurrogateValue_LaterLine_ResolvesInvalidDidLogForEveryVersion()
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var (method, _) = CreateMethod();
        var updated = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer
        });
        var lines = ((string)updated.Artifacts![DidWebVhArtifacts.DidJsonl]).Split('\n');
        var firstVersionId = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(lines[0]))[0].VersionId;
        lines[1] = WithJwkVerificationMethod(lines[1], did, """{"a":"\uD800"}""");
        var doctored = string.Join('\n', lines);

        var latest = await ResolveLogAsync(did, doctored);
        latest.ResolutionMetadata.Error.Should().Be("invalidDidLog");

        // A malformed line is a log-level parse failure, as for any other unparseable line.
        var (historicalMethod, httpClient) = CreateMethod();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(doctored));
        var historical = await historicalMethod.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = firstVersionId
        });
        historical.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Theory]
    [InlineData("""{"a":"😀"}""")]
    [InlineData("""["café"]""")]
    public async Task Issue145_Control_ValidEscapedValue_StillParses(string extensionJson)
    {
        // A well-formed surrogate PAIR and an ordinary escape must keep parsing: the decode
        // check rejects only text that cannot be decoded.
        var (did, jsonl, _) = await CreateLogAsync();
        var doctored = WithJwkVerificationMethod(jsonl.Split('\n')[0], did, extensionJson);

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().NotThrow();
    }

    [Fact]
    public async Task Issue145_Control_ValidSurrogatePairMemberName_StillParses()
    {
        var (_, jsonl, _) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl, "\"state\":{", "\"state\":{\"\\uD83D\\uDE00\":1,");

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().NotThrow();
    }

    #endregion

    #region Issue145_DataIntegrityProofValue_RawSurrogate (adversarial review)

    // HIGH stands for a raw lone surrogate char, substituted at run time: a lone surrogate
    // cannot survive in an attribute argument, which is stored as UTF-8.
    [Theory]
    [InlineData("{\"HIGH\":1,\"type\":\"DataIntegrityProof\"}")]
    [InlineData("{\"type\":\"HIGH\"}")]
    public void Issue145_ProofParse_RawLoneSurrogateChar_ThrowsJsonException(string template)
    {
        // A raw (unescaped) lone surrogate char in the .NET string fails UTF-8 transcoding with
        // ArgumentException; the documented invalid-input error is JsonException.
        var json = template.Replace("HIGH", "\uD800");
        var act = () => DataIntegrityProofValue.Parse(json);

        act.Should().Throw<System.Text.Json.JsonException>();
    }

    [Fact]
    public void Issue145_ProofParse_Null_StillThrowsArgumentNullException()
    {
        var act = () => DataIntegrityProofValue.Parse(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    #endregion

    #region Issue145_WitnessAuthoring_NonCanonicalizableProof

    // A structurally valid proof whose complete JSON is outside the JCS data model. No
    // eddsa-jcs-2022 verifier can check it. Resolution treats it as one invalid proof; on the
    // authoring path it used to escape Create/Update/Deactivate as NetCid.JcsFormatException.
    private static string NonCanonicalizableProof(string extension) =>
        "{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\"," +
        "\"verificationMethod\":\"did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" +
        "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK\"," +
        "\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"z3abc\"," + extension + "}";

    public static TheoryData<string> NonCanonicalizableExtensions => new()
    {
        "\"x-ext\":\"\\uD800\"",
        "\"x-ext\":1e400",
        "\"id\":\"urn:\\uD800\"",
    };

    private static WitnessProofEntry[] WitnessProofsWith(string extension) =>
    [
        new WitnessProofEntry
        {
            VersionId = "1-QmA",
            Proofs = [DataIntegrityProofValue.Parse(NonCanonicalizableProof(extension))]
        }
    ];

    private static byte[] WitnessFileWith(string extension) => Encoding.UTF8.GetBytes(
        "[{\"versionId\":\"1-QmA\",\"proof\":[" + NonCanonicalizableProof(extension) + "]}]");

    [Theory]
    [MemberData(nameof(NonCanonicalizableExtensions))]
    public async Task Issue145_Update_NonCanonicalizableWitnessProof_ThrowsArgumentException(string extension)
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            WitnessProofs = WitnessProofsWith(extension)
        });

        (await act.Should().ThrowAsync<ArgumentException>())
            .Which.ParamName.Should().Be(nameof(DidWebVhUpdateOptions.WitnessProofs));
    }

    [Fact]
    public async Task Issue145_Create_NonCanonicalizableWitnessProof_ThrowsArgumentException()
    {
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto);
        var (method, _) = CreateMethod();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            WitnessProofs = WitnessProofsWith("\"x-ext\":1e400")
        });

        (await act.Should().ThrowAsync<ArgumentException>())
            .Which.ParamName.Should().Be(nameof(DidWebVhCreateOptions.WitnessProofs));
    }

    [Fact]
    public async Task Issue145_Deactivate_NonCanonicalizableWitnessProof_ThrowsArgumentException()
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var (method, _) = CreateMethod();

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            WitnessProofs = WitnessProofsWith("\"x-ext\":\"\\uD800\"")
        });

        (await act.Should().ThrowAsync<ArgumentException>())
            .Which.ParamName.Should().Be(nameof(DidWebVhDeactivateOptions.WitnessProofs));
    }

    [Theory]
    [MemberData(nameof(NonCanonicalizableExtensions))]
    public async Task Issue145_Update_NonCanonicalizableProofInWitnessContent_ThrowsArgumentException(
        string extension)
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            CurrentWitnessContent = WitnessFileWith(extension)
        });

        (await act.Should().ThrowAsync<ArgumentException>())
            .Which.ParamName.Should().Be(nameof(DidWebVhUpdateOptions.CurrentWitnessContent));
    }

    [Fact]
    public async Task Issue145_Deactivate_NonCanonicalizableProofInWitnessContent_ThrowsArgumentException()
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var (method, _) = CreateMethod();

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            CurrentWitnessContent = WitnessFileWith("\"x-ext\":1e400")
        });

        (await act.Should().ThrowAsync<ArgumentException>())
            .Which.ParamName.Should().Be(nameof(DidWebVhDeactivateOptions.CurrentWitnessContent));
    }

    [Theory]
    [MemberData(nameof(NonCanonicalizableExtensions))]
    public void Issue145_Guard_ResolutionParserStillAcceptsNonCanonicalizableProof(string extension)
    {
        // Resolution must keep treating such a proof as one invalid proof inside an otherwise
        // usable witness file (PR #143), so the file parser must not start rejecting it.
        var parsed = WitnessValidator.ParseWitnessFile(WitnessFileWith(extension), out var parseError);

        parsed.Should().NotBeNull();
        parseError.Should().BeNull();
    }

    #endregion

    #region Issue145_MalformedStateShapes (round-3 adversarial review, pre-existing)

    [Theory]
    [InlineData("\"type\":\"Multikey\"", "\"type\":null")]
    [InlineData("\"verificationMethod\":[", "\"verificationMethod\":[null,")]
    public async Task Issue145_StateShapeThatCrashedTheModel_ResolvesInvalidDidLog(string find, string replace)
    {
        // These used to throw NullReferenceException inside the state's document model, which
        // escaped the parse boundary and resolved as notFound.
        var (did, jsonl, _) = await CreateLogAsync();
        var doctored = DoctorGenesisLine(jsonl, find, replace);

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().Throw<FormatException>();

        var result = await ResolveLogAsync(did, doctored);
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    #endregion

    #region Issue145_AuthoringRejectsUnpairedSurrogates (round 4, writer side)

    // Utf8JsonWriter silently replaces an unpaired surrogate with U+FFFD, so these used to
    // publish a log whose bytes differ from the caller's input while reporting success.

    [Fact]
    public async Task Issue145_Create_ServiceWithUnpairedSurrogate_ThrowsArgumentException()
    {
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto);
        var (method, _) = CreateMethod();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "Linked\uD800Domains",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com")
                }
            ]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue145_Create_PreRotationCommitmentWithUnpairedSurrogate_ThrowsArgumentException()
    {
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto);
        var (method, _) = CreateMethod();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            PreRotationCommitments = ["Qm\uD800"]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue145_Create_WatcherWithUnpairedSurrogate_ThrowsArgumentException()
    {
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto);
        var (method, _) = CreateMethod();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Watchers = ["https://watcher.example/\uD800"]
        });

        // System.Uri accepts it, so the watcher URL check alone never caught this.
        await act.Should().ThrowAsync<ArgumentException>(
            "a watcher URL that cannot be encoded must never be published as U+FFFD");
    }

    [Fact]
    public async Task Issue145_Update_NewDocumentWithUnpairedSurrogate_ThrowsArgumentException()
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var current = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(jsonl))[0].State;
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            NewDocument = current with { AlsoKnownAs = ["https://alias.example/\uD800"] }
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task Issue145_Create_ServiceExtensionWithIllFormedUtf8_ThrowsArgumentException()
    {
        // PR #149 review/final pass: a caller JsonElement holding ill-formed UTF-8 was written as
        // U+FFFD into a signed, resolvable did.jsonl and into did.json.
        byte[] utf8 = [.. "\"a"u8.ToArray(), 0xED, 0xA0, 0x80, .. "b\""u8.ToArray()];
        using var document = System.Text.Json.JsonDocument.Parse(utf8);
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto);
        var (method, _) = CreateMethod();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services =
            [
                new Service
                {
                    Id = "#svc",
                    Type = "Example",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com"),
                    AdditionalProperties = new Dictionary<string, System.Text.Json.JsonElement>
                    {
                        ["note"] = document.RootElement.Clone()
                    }
                }
            ]
        });

        await act.Should().ThrowAsync<ArgumentException>();
    }

    // F3 (final pass): did.json projects the document onto did:web. A service already in the
    // did:web form must count as the #whois override there, not get a second, implicit #whois.
    [Fact]
    public async Task Issue145_Create_DidWebFormWhoisOverride_ProjectsOneWhois()
    {
        var signer = new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto);
        var (method, _) = CreateMethod();

        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services =
            [
                new Service
                {
                    Id = "did:web:example.com#whois",
                    Type = "LinkedVerifiablePresentation",
                    ServiceEndpoint = ServiceEndpointValue.FromUri("https://example.com/custom-whois.vp")
                }
            ]
        });

        var didJson = DidDocumentSerializer.Deserialize((string)created.Artifacts![DidWebVhArtifacts.DidJson]);
        didJson.Service!.Count(service => service.Id.EndsWith("#whois", StringComparison.Ordinal))
            .Should().Be(1);
    }

    [Fact]
    public async Task Issue145_Create_ServicesCollidingInDidJson_ThrowsBeforeSigning()
    {
        // "did:web:example.com#x" and "#x" are distinct in the did:webvh document but name the
        // same service in the parallel did.json, which must never carry duplicate ids. The
        // projection is built before signing, so no signature is spent on a refused document.
        var signer = new CountingSigner(new KeyPairSigner(_keyGen.Generate(KeyType.Ed25519), _crypto));
        var (method, _) = CreateMethod();

        var act = () => method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer,
            Services = CollidingInDidJson
        });

        await act.Should().ThrowAsync<ArgumentException>();
        signer.Calls.Should().Be(0);
    }

    [Fact]
    public async Task Issue145_Update_ServicesCollidingInDidJson_ThrowsBeforeSigning()
    {
        var (did, jsonl, inner) = await CreateLogAsync();
        var current = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(jsonl))[0].State;
        var signer = new CountingSigner(inner);
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            NewDocument = current with { Service = CollidingInDidJson }
        });

        await act.Should().ThrowAsync<ArgumentException>();
        signer.Calls.Should().Be(0);
    }

    private static List<Service> CollidingInDidJson =>
    [
        new Service { Id = "did:web:example.com#x", Type = "A", ServiceEndpoint = ServiceEndpointValue.FromUri("https://a.example") },
        new Service { Id = "#x", Type = "B", ServiceEndpoint = ServiceEndpointValue.FromUri("https://b.example") }
    ];

    private sealed class CountingSigner(ISigner inner) : ISigner
    {
        public int Calls { get; private set; }
        public KeyType KeyType => inner.KeyType;
        public ReadOnlyMemory<byte> PublicKey => inner.PublicKey;
        public string MultibasePublicKey => inner.MultibasePublicKey;

        public Task<byte[]> SignAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
        {
            Calls++;
            return inner.SignAsync(data, ct);
        }
    }

    private static DataIntegrityProofValue ProgrammaticProof(string proofValue) => new()
    {
        Type = "DataIntegrityProof",
        Cryptosuite = "eddsa-jcs-2022",
        VerificationMethod = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" +
            "#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        ProofPurpose = "assertionMethod",
        ProofValue = proofValue
    };

    public static TheoryData<string> MalformedWitnessInputs => new()
    {
        "proof-value-surrogate", "version-id-surrogate", "null-entry", "null-proofs", "null-proof",
        "null-version-id",
    };

    private static WitnessProofEntry?[] WitnessInput(string kind) => kind switch
    {
        "proof-value-surrogate" =>
            [new WitnessProofEntry { VersionId = "1-QmA", Proofs = [ProgrammaticProof("z3\uD800abc")] }],
        "version-id-surrogate" =>
            [new WitnessProofEntry { VersionId = "1-Qm\uD800A", Proofs = [ProgrammaticProof("z3abc")] }],
        "null-entry" => [null],
        "null-proofs" => [new WitnessProofEntry { VersionId = "1-QmA", Proofs = null! }],
        "null-proof" => [new WitnessProofEntry { VersionId = "1-QmA", Proofs = [null!] }],
        "null-version-id" =>
            [new WitnessProofEntry { VersionId = null!, Proofs = [ProgrammaticProof("z3abc")] }],
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    [Theory]
    [MemberData(nameof(MalformedWitnessInputs))]
    public async Task Issue145_Update_MalformedWitnessInput_ThrowsArgumentException(string kind)
    {
        var (did, jsonl, signer) = await CreateLogAsync();
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(jsonl),
            SigningKey = signer,
            WitnessProofs = WitnessInput(kind)!
        });

        (await act.Should().ThrowAsync<ArgumentException>())
            .Which.ParamName.Should().Be(nameof(DidWebVhUpdateOptions.WitnessProofs));
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
