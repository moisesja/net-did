using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DataProofsDotnet;
using DataProofsDotnet.DataIntegrity;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Exceptions;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Regression tests for issue #101: did:webvh multi-proof validation accepted invalid or
/// unauthorized extra proofs.
///
/// Before the fix, <c>LogChainValidator.ValidateProof</c> implemented an existential rule —
/// the entry was accepted as soon as one proof verified from an active update key, silently
/// skipping every other supplied proof. did:webvh v1.0 §Authorized Keys requires the
/// opposite: "Resolvers MUST reject an entry whose proof fails any check." Verification now
/// delegates every proof to DataProofsDotnet's Data Integrity pipeline with a did:webvh
/// authorization resolver, an <c>assertionMethod</c> purpose expectation, and an
/// <c>expires</c> policy pinned to the entry's <c>versionTime</c>. These tests pin the
/// universal rule (every supplied controller proof must verify and be authorized; one
/// authorized signer suffices; no threshold semantics), support for schema-defined members
/// (<c>id</c>, <c>expires</c>) and their semantics, the single-proof-object shape, optional
/// <c>created</c>, rejection of duplicate JSON members and malformed content
/// (<c>invalidDidLog</c>), and the explicit per-entry proof budget.
/// </summary>
public class LogChainValidatorMultiProofTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    // ================================================================
    // Helpers
    // ================================================================

    private (DidWebVhMethod Method, MockWebVhHttpClient HttpClient) CreateMethod()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        return (method, httpClient);
    }

    private (KeyPair KeyPair, ISigner Signer) CreateEd25519()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        return (keyPair, new KeyPairSigner(keyPair, _crypto));
    }

    private async Task<(string Did, List<LogEntry> Entries, string Jsonl)> CreateLogAsync(
        ISigner authorizedSigner)
    {
        var (method, _) = CreateMethod();
        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = authorizedSigner
        });

        var jsonl = (string)result.Artifacts![DidWebVhArtifacts.DidJsonl];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(jsonl)).ToList();
        return (result.Did.Value, entries, jsonl);
    }

    /// <summary>
    /// Signs <paramref name="entry"/> (serialized without proof) with the conformant
    /// eddsa-jcs-2022 suite. The signature genuinely covers the produced proof
    /// configuration, so wrong-purpose or extra-member proofs built here are exactly what
    /// a conforming (or hostile) foreign implementation would emit.
    /// </summary>
    private async Task<DataIntegrityProofValue> SignEntryAsync(
        LogEntry entry,
        KeyPair keyPair,
        string proofPurpose = "assertionMethod",
        string? created = null,
        string? expires = null,
        string? id = null,
        PreviousProofReference? previousProof = null,
        IReadOnlyList<string>? arrayDomain = null)
    {
        var vm = $"did:key:{keyPair.MultibasePublicKey}#{keyPair.MultibasePublicKey}";
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = vm,
            Created = created,
            Expires = expires,
            Id = id,
            ProofPurpose = proofPurpose,
            PreviousProof = previousProof,
            // The pinned DataProofsDotnet model exposes domain as string?, but its low-level
            // suite still signs an array-valued domain when supplied as an extension. This
            // lets the integration test characterize the high-level pipeline limitation with
            // a cryptographically self-consistent proof.
            AdditionalProperties = arrayDomain is null
                ? null
                : new Dictionary<string, JsonElement>
                {
                    ["domain"] = JsonSerializer.SerializeToElement(arrayDomain)
                }
        };

        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entry);
        using var document = JsonDocument.Parse(entryJsonWithoutProof);
        var suite = new EddsaJcs2022Cryptosuite();
        var proof = await suite.CreateProofAsync(
            document.RootElement, proofOptions, new KeyPairSigner(keyPair, _crypto));
        suite.VerifyProof(
                document.RootElement,
                proof,
                PublicKeyMaterial.FromMultikey(keyPair.MultibasePublicKey))
            .Verified.Should().BeTrue(
                "the helper must produce a self-consistent signature before policy validation");

        return new DataIntegrityProofValue
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite!,
            VerificationMethod = proof.VerificationMethod!,
            Created = proof.Created,
            ProofPurpose = proof.ProofPurpose!,
            ProofValue = proof.ProofValue!,
            // Verbatim signed proof JSON: carries any id/expires so the signature covers them
            // and they round-trip, exactly as a foreign implementation's proof would.
            RawJson = JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default)
        };
    }

    /// <summary>Copies a proof with a different created value, invalidating its signature.</summary>
    private static DataIntegrityProofValue WithBrokenSignature(DataIntegrityProofValue proof)
        => new()
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite,
            VerificationMethod = proof.VerificationMethod,
            Created = "2001-01-01T00:00:00Z",
            ProofPurpose = proof.ProofPurpose,
            ProofValue = proof.ProofValue
        };

    private static byte[] SerializeLog(IEnumerable<LogEntry> entries)
        => LogEntrySerializer.ToJsonLines(entries.ToList());

    private static string MutateGenesisLine(string jsonl, Action<JsonObject> mutate)
    {
        var lines = jsonl.Split('\n');
        var node = JsonNode.Parse(lines[0])!.AsObject();
        mutate(node);
        lines[0] = node.ToJsonString();
        return string.Join('\n', lines);
    }

    private async Task<DidResolutionResult> ResolveLogAsync(string did, byte[] log)
    {
        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), log);
        return await method.ResolveAsync(did);
    }

    // ================================================================
    // Universal validation: extra invalid/unauthorized proofs reject
    // ================================================================

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Issue101_ValidPlusUnauthorizedProof_EitherOrder_ResolvesInvalidDidLog(
        bool unauthorizedFirst)
    {
        var (_, authorizedSigner) = CreateEd25519();
        var (attackerKp, _) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(authorizedSigner);

        var authorizedProof = entries[0].Proof![0];
        var unauthorizedProof = await SignEntryAsync(
            entries[0], attackerKp, created: authorizedProof.Created);

        entries[0] = entries[0] with
        {
            Proof = unauthorizedFirst
                ? [unauthorizedProof, authorizedProof]
                : [authorizedProof, unauthorizedProof]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Issue101_ValidPlusInvalidSignatureProof_EitherOrder_ResolvesInvalidDidLog(
        bool invalidFirst)
    {
        var (_, authorizedSigner) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(authorizedSigner);

        var authorizedProof = entries[0].Proof![0];
        // Same authorized signer/VM, but the created value no longer matches the signed
        // proof configuration — a syntactically valid proof whose signature fails.
        var brokenProof = WithBrokenSignature(authorizedProof);

        entries[0] = entries[0] with
        {
            Proof = invalidFirst
                ? [brokenProof, authorizedProof]
                : [authorizedProof, brokenProof]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_OnlyUnauthorizedProofs_ResolvesInvalidDidLog()
    {
        var (_, authorizedSigner) = CreateEd25519();
        var (attacker1, _) = CreateEd25519();
        var (attacker2, _) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(authorizedSigner);

        var created = entries[0].Proof![0].Created;
        entries[0] = entries[0] with
        {
            Proof =
            [
                await SignEntryAsync(entries[0], attacker1, created: created),
                await SignEntryAsync(entries[0], attacker2, created: created)
            ]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_ValidateChain_MixedProofs_Throws()
    {
        // The issue's direct reproduction: genesis with an unauthorized-but-valid proof
        // ahead of the authorized one previously validated successfully.
        var (_, authorizedSigner) = CreateEd25519();
        var (attackerKp, _) = CreateEd25519();
        var (_, entries, _) = await CreateLogAsync(authorizedSigner);

        var authorizedProof = entries[0].Proof![0];
        var unauthorizedProof = await SignEntryAsync(
            entries[0], attackerKp, created: authorizedProof.Created);
        var mixed = entries[0] with { Proof = [unauthorizedProof, authorizedProof] };

        var act = () => new LogChainValidator()
            .ValidateChain([mixed]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*Proof validation failed*");
    }

    // ================================================================
    // Multiple valid authorized proofs stay supported (no threshold)
    // ================================================================

    [Fact]
    public async Task Issue101_MultipleValidAuthorizedProofs_Resolves()
    {
        var (kpA, signerA) = CreateEd25519();
        var (kpB, _) = CreateEd25519();
        var (method, httpClient) = CreateMethod();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signerA
        });
        var did = createResult.Did.Value;

        // v2 declares updateKeys [A, B]; v3 is then authorized by both.
        var update1 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = signerA,
            ParameterUpdates = new DidWebVhParameterUpdates
            {
                UpdateKeys = [kpA.MultibasePublicKey, kpB.MultibasePublicKey]
            }
        });
        var update2 = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)update1.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = signerA
        });

        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(
            (string)update2.Artifacts![DidWebVhArtifacts.DidJsonl])).ToList();

        // Replace v3's proof with two valid proofs from the two active update keys.
        var created = entries[2].Proof![0].Created;
        entries[2] = entries[2] with
        {
            Proof =
            [
                await SignEntryAsync(entries[2], kpA, created: created),
                await SignEntryAsync(entries[2], kpB, created: created)
            ]
        };

        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));
        var result = await method.ResolveAsync(did);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    // ================================================================
    // Per-proof policy: proofPurpose / type / cryptosuite
    // ================================================================

    [Fact]
    public async Task Issue101_WrongProofPurpose_ResolvesInvalidDidLog()
    {
        // Validly signed by the authorized key, but over proofPurpose "authentication".
        // did:webvh requires assertionMethod; before the fix this resolved successfully.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var created = entries[0].Proof![0].Created;
        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(entries[0], kpA, proofPurpose: "authentication", created: created)]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_ValidateChain_WrongType_ThrowsPolicyError()
    {
        var (_, signerA) = CreateEd25519();
        var (_, entries, _) = await CreateLogAsync(signerA);

        var original = entries[0].Proof![0];
        var wrongType = new DataIntegrityProofValue
        {
            Type = "Ed25519Signature2020",
            Cryptosuite = original.Cryptosuite,
            VerificationMethod = original.VerificationMethod,
            Created = original.Created,
            ProofPurpose = original.ProofPurpose,
            ProofValue = original.ProofValue
        };
        var tampered = entries[0] with { Proof = [original, wrongType] };

        var act = () => new LogChainValidator()
            .ValidateChain([tampered]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*version 1*");
    }

    [Fact]
    public async Task Issue101_ValidateChain_WrongCryptosuite_ThrowsPolicyError()
    {
        var (_, signerA) = CreateEd25519();
        var (_, entries, _) = await CreateLogAsync(signerA);

        var original = entries[0].Proof![0];
        var wrongSuite = new DataIntegrityProofValue
        {
            Type = original.Type,
            Cryptosuite = "eddsa-rdfc-2022",
            VerificationMethod = original.VerificationMethod,
            Created = original.Created,
            ProofPurpose = original.ProofPurpose,
            ProofValue = original.ProofValue
        };
        var tampered = entries[0] with { Proof = [original, wrongSuite] };

        var act = () => new LogChainValidator()
            .ValidateChain([tampered]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*version 1*");
    }

    // ================================================================
    // Schema shapes: single proof object, empty/missing proof
    // ================================================================

    [Fact]
    public async Task Issue101_SingleProofObject_ParsesAndResolves()
    {
        // The official log-entry schema permits proof as one object or an array.
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var singleObjectLog = MutateGenesisLine(jsonl, node =>
            node["proof"] = node["proof"]![0]!.DeepClone());

        var parsed = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(singleObjectLog));
        parsed[0].Proof.Should().HaveCount(1);

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(singleObjectLog));

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_EmptyProofArray_ResolvesInvalidDidLog()
    {
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var emptyProofLog = MutateGenesisLine(jsonl, node => node["proof"] = new JsonArray());

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(emptyProofLog));
        parse.Should().Throw<FormatException>().WithMessage("*at least one proof*");

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(emptyProofLog));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_MissingProof_ResolvesInvalidDidLog()
    {
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var noProofLog = MutateGenesisLine(jsonl, node => node.Remove("proof"));

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(noProofLog));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    // ================================================================
    // Structural malformations: FormatException → invalidDidLog
    // ================================================================

    [Theory]
    [InlineData("missing-member")]
    [InlineData("non-string-member")]
    [InlineData("null-member")]
    [InlineData("non-object-element")]
    [InlineData("non-object-non-array-proof")]
    [InlineData("null-id")]
    [InlineData("empty-id")]
    [InlineData("non-string-id")]
    public async Task Issue101_MalformedProof_ThrowsFormatException_AndResolvesInvalidDidLog(
        string malformation)
    {
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var malformedLog = MutateGenesisLine(jsonl, node =>
        {
            switch (malformation)
            {
                case "missing-member":
                    node["proof"]![0]!.AsObject().Remove("proofValue");
                    break;
                case "non-string-member":
                    node["proof"]![0]!["proofValue"] = 42;
                    break;
                case "null-member":
                    node["proof"]![0]!["type"] = null;
                    break;
                case "non-object-element":
                    node["proof"] = new JsonArray(JsonValue.Create("bogus"));
                    break;
                case "non-object-non-array-proof":
                    node["proof"] = JsonValue.Create("bogus");
                    break;
                case "null-id":
                    node["proof"]![0]!["id"] = null;
                    break;
                case "empty-id":
                    node["proof"]![0]!["id"] = "";
                    break;
                case "non-string-id":
                    node["proof"]![0]!["id"] = 42;
                    break;
            }
        });

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(malformedLog));
        parse.Should().Throw<FormatException>();

        // Malformed log content is invalidDidLog, never notFound (and never an unhandled
        // KeyNotFoundException / InvalidOperationException).
        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(malformedLog));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_MalformedExtraProofBesideValidOne_ResolvesInvalidDidLog()
    {
        // A structurally broken EXTRA proof next to the valid one must not be skippable.
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var malformedLog = MutateGenesisLine(jsonl, node =>
        {
            var broken = node["proof"]![0]!.DeepClone().AsObject();
            broken.Remove("proofValue");
            node["proof"]!.AsArray().Add(broken);
        });

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(malformedLog));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    // ================================================================
    // Interop: optional created (schema-permitted)
    // ================================================================

    [Fact]
    public async Task Issue101_ProofWithoutCreated_Resolves()
    {
        // created is optional in the official log-entry schema's proof definition.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(entries[0], kpA, created: null)]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    // ================================================================
    // Schema-defined proof members (id, expires) are supported and their
    // semantics enforced via the Data Integrity pipeline (PR #102 review, finding 2)
    // ================================================================

    [Fact]
    public async Task Issue101_SignedProofWithFutureExpires_Resolves()
    {
        // expires is schema-defined and additionalProperties is open, so a genuinely signed
        // proof with a future expires must verify (not be rejected as unsupported).
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(entries[0], kpA,
                created: entries[0].Proof![0].Created, expires: "2099-12-31T23:59:59Z")]
        };
        var log = SerializeLog(entries);
        Encoding.UTF8.GetString(log).Should().Contain("\"expires\"");

        var result = await ResolveLogAsync(did, log);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_SignedProofWithPastExpires_ResolvesInvalidDidLog()
    {
        // A proof whose expires precedes the entry's versionTime is expired: the resolver
        // enforces the expires policy against versionTime and rejects it.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(entries[0], kpA,
                created: entries[0].Proof![0].Created, expires: "2000-01-01T00:00:00Z")]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Theory]
    [InlineData("urn:proof:1")]
    [InlineData("did:example:proof-1")]
    [InlineData("https://proof.example/1")]
    public async Task Issue101_SignedProofWithId_Resolves(string proofId)
    {
        // id is schema-defined; a genuinely signed proof carrying it must verify and the id
        // must round-trip on re-serialization.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(entries[0], kpA,
                created: entries[0].Proof![0].Created, id: proofId)]
        };
        var log = SerializeLog(entries);
        Encoding.UTF8.GetString(log).Should().Contain(proofId);

        var result = await ResolveLogAsync(did, log);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_SignedProofWithInvalidId_ResolvesInvalidDidLog()
    {
        // Data Integrity requires a present proof id to be a URL. This proof is genuinely
        // signed over the invalid id, so rejection cannot be attributed to signature failure.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(entries[0], kpA,
                created: entries[0].Proof![0].Created, id: "not a URL")]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_SignedProofWithDanglingPreviousProof_ResolvesInvalidDidLog()
    {
        // A previousProof reference that matches no proof id in the entry is a dangling chain
        // reference. The proof is signed with previousProof already in its configuration, so
        // this test cannot pass merely because the test mutated a valid proof after signing.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(
                entries[0], kpA,
                created: entries[0].Proof![0].Created,
                previousProof: PreviousProofReference.FromSingle("urn:missing"))]
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_GenuineTwoProofChain_Resolves()
    {
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);
        const string firstProofId = "urn:proof:chain-root";
        var verificationMethod =
            $"did:key:{kpA.MultibasePublicKey}#{kpA.MultibasePublicKey}";
        var created = entries[0].Proof![0].Created;
        var pipeline = new DataIntegrityProofPipeline();
        var signer = new KeyPairSigner(kpA, _crypto);

        using var unsecured = JsonDocument.Parse(
            LogEntrySerializer.SerializeWithoutProof(entries[0]));
        var withFirst = await pipeline.AddProofAsync(unsecured.RootElement, new DataIntegrityProof
        {
            Id = firstProofId,
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = verificationMethod,
            Created = created,
            ProofPurpose = "assertionMethod"
        }, signer);
        var withChain = await pipeline.AddProofAsync(withFirst, new DataIntegrityProof
        {
            Id = "urn:proof:chain-child",
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = verificationMethod,
            Created = created,
            ProofPurpose = "assertionMethod",
            PreviousProof = PreviousProofReference.FromSingle(firstProofId)
        }, signer);

        var result = await ResolveLogAsync(
            did, Encoding.UTF8.GetBytes(withChain.GetRawText()));

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_ArrayValuedDomain_PinnedPipelineRejectsUpstreamLimitation()
    {
        // W3C Data Integrity permits domain as an unordered set of strings. The low-level stock
        // suite signs this representation, but the pinned pipeline models domain as string? and
        // therefore rejects it during proof deserialization. Keep this characterization explicit
        // until DataProofsDotnet publishes a string-or-set model.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        entries[0] = entries[0] with
        {
            Proof = [await SignEntryAsync(
                entries[0], kpA,
                created: entries[0].Proof![0].Created,
                arrayDomain: ["domain.example", "https://domain.example:8443"])]
        };
        var log = SerializeLog(entries);
        Encoding.UTF8.GetString(log).Should().Contain(
            "\"domain\":[\"domain.example\",\"https://domain.example:8443\"]");

        var result = await ResolveLogAsync(did, log);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    // ================================================================
    // Malformed Unicode escapes map to invalidDidLog (PR #102 review, finding 3)
    // ================================================================

    [Fact]
    public async Task Issue101_ProofWithUnpairedSurrogate_ResolvesInvalidDidLog()
    {
        // "\uD800" is a token JsonDocument.Parse accepts but GetString throws on. The parse
        // boundary must map that to FormatException -> invalidDidLog, never notFound.
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var line = jsonl.Split('\n')[0];
        var doctored = line.Replace(
            "\"proofPurpose\":\"assertionMethod\"", "\"proofPurpose\":\"\\uD800\"");

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().Throw<FormatException>();

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(doctored));
        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    // ================================================================
    // Duplicate JSON members cannot smuggle an unvalidated proof (PR #102 review, finding 1)
    // ================================================================

    [Fact]
    public async Task Issue101_DuplicateTopLevelProofMember_ResolvesInvalidDidLog()
    {
        // .NET keeps the last of a duplicate pair. A leading decoy "proof" beside the valid
        // trailing one is an extra supplied proof that was never validated — the exact
        // invariant this fix establishes. Duplicate members must reject the whole entry.
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var line = jsonl.Split('\n')[0];
        // Inject a decoy proof member ahead of the existing one via raw text. "proof": is the
        // top-level member (distinct from "proofPurpose"/"proofValue"), so it occurs once.
        var doctored = line.Replace(
            "\"proof\":", "\"proof\":[{\"type\":\"bogus\"}],\"proof\":");

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().Throw<FormatException>();

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(doctored));
        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_DuplicateMemberInsideProofObject_ResolvesInvalidDidLog()
    {
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var line = jsonl.Split('\n')[0];
        // Duplicate proofPurpose inside the proof object with a non-conforming last value.
        var doctored = line.Replace(
            "\"proofPurpose\":\"assertionMethod\"",
            "\"proofPurpose\":\"assertionMethod\",\"proofPurpose\":\"authentication\"");

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(doctored));
        parse.Should().Throw<FormatException>();

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(doctored));
        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    // ================================================================
    // Update/Deactivate surface malformed proof content as FormatException (finding 4)
    // ================================================================

    [Fact]
    public async Task Issue101_Update_OnMalformedProofLog_ThrowsFormatException()
    {
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var malformed = MutateGenesisLine(jsonl, node => node["proof"]![0]!.AsObject().Remove("proofValue"));
        var (method, _) = CreateMethod();

        var act = () => method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(malformed),
            SigningKey = signerA
        });

        await act.Should().ThrowAsync<FormatException>();
    }

    [Fact]
    public async Task Issue101_Deactivate_OnMalformedProofLog_ThrowsFormatException()
    {
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var malformed = MutateGenesisLine(jsonl, node => node["proof"]![0]!["proofValue"] = 42);
        var (method, _) = CreateMethod();

        var act = () => method.DeactivateAsync(did, new DidWebVhDeactivateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(malformed),
            SigningKey = signerA
        });

        await act.Should().ThrowAsync<FormatException>();
    }

    // ================================================================
    // Verification work is bounded by an explicit proof budget (PR #102 review, finding 1)
    // ================================================================

    [Fact]
    public async Task Issue101_ProofCountAtBudget_Resolves()
    {
        // A count at the budget resolves (the budget bounds work; it does not reject small
        // multi-proof entries). These are distinct valid proofs from one key (varying created),
        // which the false "distinct <= active keys" claim wrongly assumed impossible.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var baseInstant = DateTimeOffset.Parse(entries[0].Proof![0].Created!).UtcDateTime;
        var proofs = new List<DataIntegrityProofValue>();
        for (int i = 0; i < LogChainValidator.DefaultMaxControllerProofsPerEntry; i++)
        {
            var created = baseInstant.AddSeconds(-1 - i).ToString("yyyy-MM-ddTHH:mm:ssZ");
            proofs.Add(await SignEntryAsync(entries[0], kpA, created: created));
        }
        entries[0] = entries[0] with { Proof = proofs };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_DistinctValidProofsBeyondBudget_ResolvesInvalidDidLog()
    {
        // The reviewer's amplification repro: one key mints many DISTINCT valid proofs by
        // varying created. Beyond the budget the entry is rejected, bounding verification work.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var baseInstant = DateTimeOffset.Parse(entries[0].Proof![0].Created!).UtcDateTime;
        var proofs = new List<DataIntegrityProofValue>();
        for (int i = 0; i < LogChainValidator.DefaultMaxControllerProofsPerEntry + 1; i++)
        {
            var created = baseInstant.AddSeconds(-1 - i).ToString("yyyy-MM-ddTHH:mm:ssZ");
            proofs.Add(await SignEntryAsync(entries[0], kpA, created: created));
        }
        entries[0] = entries[0] with { Proof = proofs };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_RaisedPublicBudget_AllowsDistinctProofsAboveDefault()
    {
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);
        var raisedBudget = LogChainValidator.DefaultMaxControllerProofsPerEntry + 1;
        var baseInstant = DateTimeOffset.Parse(entries[0].Proof![0].Created!).UtcDateTime;
        var proofs = new List<DataIntegrityProofValue>();
        for (var i = 0; i < raisedBudget; i++)
        {
            var created = baseInstant.AddSeconds(-1 - i).ToString("yyyy-MM-ddTHH:mm:ssZ");
            proofs.Add(await SignEntryAsync(entries[0], kpA, created: created));
        }
        entries[0] = entries[0] with { Proof = proofs };

        var httpClient = new MockWebVhHttpClient();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));
        var method = new DidWebVhMethod(
            httpClient, logger: null, maxControllerProofsPerEntry: raisedBudget);

        var result = await method.ResolveAsync(did);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_ProofWithEmptyCreated_ResolvesInvalidDidLog()
    {
        // created:"" is present but not a valid dateTimeStamp; every supplied proof must verify,
        // so an entry pairing a valid proof with this one is rejected.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var valid = await SignEntryAsync(entries[0], kpA, created: null);
        var invalidEmptyCreated = new DataIntegrityProofValue
        {
            Type = valid.Type,
            Cryptosuite = valid.Cryptosuite,
            VerificationMethod = valid.VerificationMethod,
            Created = "",                       // present-but-empty: not a valid dateTimeStamp
            ProofPurpose = valid.ProofPurpose,
            ProofValue = valid.ProofValue
        };
        entries[0] = entries[0] with { Proof = [valid, invalidEmptyCreated] };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    // ================================================================
    // IncludeLog never exposes an unchecked proof collection
    // ================================================================

    [Fact]
    public async Task Issue101_IncludeLog_MixedProofs_ExposesNoArtifacts()
    {
        var (_, authorizedSigner) = CreateEd25519();
        var (attackerKp, _) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(authorizedSigner);

        var authorizedProof = entries[0].Proof![0];
        var unauthorizedProof = await SignEntryAsync(
            entries[0], attackerKp, created: authorizedProof.Created);
        entries[0] = entries[0] with { Proof = [unauthorizedProof, authorizedProof] };

        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));

        var result = await method.ResolveAsync(
            did, new DidResolutionOptions { IncludeLog = true });

        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
        result.Artifacts.Should().BeNull();
    }

    [Fact]
    public async Task Issue101_HistoricalIncludeLog_ExcludesGenuinelyUnauthorizedTailProof()
    {
        var (_, authorizedSigner) = CreateEd25519();
        var (attackerKey, _) = CreateEd25519();
        var (method, httpClient) = CreateMethod();
        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = authorizedSigner
        });
        var did = created.Did.Value;
        var updated = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = Encoding.UTF8.GetBytes(
                (string)created.Artifacts![DidWebVhArtifacts.DidJsonl]),
            SigningKey = authorizedSigner
        });
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(
            (string)updated.Artifacts![DidWebVhArtifacts.DidJsonl])).ToList();

        var authorizedProof = entries[1].Proof![0];
        var unauthorizedProof = await SignEntryAsync(
            entries[1], attackerKey, created: authorizedProof.Created);
        entries[1] = entries[1] with { Proof = [authorizedProof, unauthorizedProof] };
        var hostileLog = Encoding.UTF8.GetString(SerializeLog(entries));
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(hostileLog));

        var result = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionId = entries[0].VersionId,
            IncludeLog = true
        });

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
        var exposed = (IReadOnlyList<LogEntry>)result.Artifacts![DidWebVhArtifacts.LogEntries];
        exposed.Should().ContainSingle()
            .Which.VersionId.Should().Be(entries[0].VersionId);
        var exposedJsonl = (string)result.Artifacts[DidWebVhArtifacts.DidJsonl];
        exposedJsonl.Should().Be(hostileLog.Split('\n')[0]);
        exposedJsonl.Should().NotContain(unauthorizedProof.ProofValue);
    }
}
