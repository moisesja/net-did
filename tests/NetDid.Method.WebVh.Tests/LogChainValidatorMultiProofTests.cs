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
/// opposite: "Resolvers MUST reject an entry whose proof fails any check." These tests pin
/// the universal rule (every supplied controller proof must be valid and authorized; one
/// authorized signer suffices; no threshold semantics), the explicit proofPurpose /
/// type / cryptosuite policy, the schema-supported single-proof-object shape, optional
/// <c>created</c>, byte-faithful round-trip of foreign proof members, and the
/// <c>invalidDidLog</c> error mapping for malformed proof content.
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
        string? created = null)
    {
        var vm = $"did:key:{keyPair.MultibasePublicKey}#{keyPair.MultibasePublicKey}";
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = vm,
            Created = created,
            ProofPurpose = proofPurpose,
        };

        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(entry);
        using var document = JsonDocument.Parse(entryJsonWithoutProof);
        var proof = await new EddsaJcs2022Cryptosuite().CreateProofAsync(
            document.RootElement, proofOptions, new KeyPairSigner(keyPair, _crypto));

        return new DataIntegrityProofValue
        {
            Type = proof.Type,
            Cryptosuite = proof.Cryptosuite!,
            VerificationMethod = proof.VerificationMethod!,
            Created = proof.Created,
            ProofPurpose = proof.ProofPurpose!,
            ProofValue = proof.ProofValue!
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

        var act = () => new LogChainValidator(new EddsaJcs2022Cryptosuite())
            .ValidateChain([mixed]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*not an authorized update key*");
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

        var act = () => new LogChainValidator(new EddsaJcs2022Cryptosuite())
            .ValidateChain([tampered]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*unsupported type*");
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

        var act = () => new LogChainValidator(new EddsaJcs2022Cryptosuite())
            .ValidateChain([tampered]);

        act.Should().Throw<LogChainValidationException>()
            .WithMessage("*unsupported cryptosuite*");
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
    // Profile narrowing: proofs carrying features the resolver does
    // not evaluate are rejected, not silently accepted (PR #102 review)
    // ================================================================

    [Theory]
    [InlineData("previousProof", "urn:missing-proof")]
    [InlineData("expires", "2000-01-01T00:00:00Z")]
    [InlineData("id", "not a url")]
    [InlineData("domain", "example.com")]
    [InlineData("challenge", "abc123")]
    [InlineData("@context", "https://w3id.org/security/data-integrity/v2")]
    public async Task Issue101_ProofWithUnsupportedMember_ResolvesInvalidDidLog(
        string member, string value)
    {
        // A proof carrying a Data Integrity feature outside the did:webvh controller-proof
        // profile is rejected. Accepting it would claim a validation the resolver never
        // performs (e.g. dangling previousProof, expiry policy, id-as-URL). The value is added
        // at the JSON level so it participates in the wire proof the parser must reject.
        var (_, signerA) = CreateEd25519();
        var (did, _, jsonl) = await CreateLogAsync(signerA);

        var mutated = MutateGenesisLine(jsonl, node =>
            node["proof"]![0]!.AsObject()[member] = value);

        var parse = () => LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(mutated));
        parse.Should().Throw<FormatException>().WithMessage("*unsupported member*");

        var result = await ResolveLogAsync(did, Encoding.UTF8.GetBytes(mutated));
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
    // Work is bounded: identical proofs verified once; large entry (finding 3)
    // ================================================================

    [Fact]
    public async Task Issue101_ManyIdenticalValidProofs_Resolves()
    {
        // Removing the arbitrary count cap must not reintroduce the amplification it guarded:
        // byte-identical proofs are verified once (dedup), so a large repeated-proof array
        // still resolves without re-canonicalizing the entry thousands of times.
        var (_, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var proof = entries[0].Proof![0];
        entries[0] = entries[0] with { Proof = Enumerable.Repeat(proof, 5000).ToList() };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_DedupDoesNotSkipDistinctCreatedVariant_ResolvesInvalidDidLog()
    {
        // Dedup must not collide a valid created-less proof with a distinct invalid proof that
        // only differs by carrying created:"" (a different, and invalid, signed configuration).
        // A joined-string identity that maps null and "" to the same key would skip the invalid
        // proof and wrongly accept the entry (PR #102 review, adversarial finding F1).
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var validNoCreated = await SignEntryAsync(entries[0], kpA, created: null);
        var invalidEmptyCreated = new DataIntegrityProofValue
        {
            Type = validNoCreated.Type,
            Cryptosuite = validNoCreated.Cryptosuite,
            VerificationMethod = validNoCreated.VerificationMethod,
            Created = "",                       // present-but-empty: not a valid dateTimeStamp
            ProofPurpose = validNoCreated.ProofPurpose,
            ProofValue = validNoCreated.ProofValue
        };
        entries[0] = entries[0] with { Proof = [validNoCreated, invalidEmptyCreated] };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Issue101_LargeEntryWithRepeatedProofs_Resolves()
    {
        // Realistically large entry (many services) with repeated proofs: dedup bounds the
        // per-proof whole-document canonicalization work to one verification.
        var (kpA, signerA) = CreateEd25519();
        var (method, httpClient) = CreateMethod();

        var services = Enumerable.Range(0, 200).Select(i => new Service
        {
            Id = $"#svc-{i}",
            Type = "TestService",
            ServiceEndpoint = ServiceEndpointValue.FromUri($"https://example.com/svc/{i}")
        }).ToList();

        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signerA,
            Services = services
        });
        var did = createResult.Did.Value;
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(
            (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl])).ToList();

        entries[0] = entries[0] with { Proof = Enumerable.Repeat(entries[0].Proof![0], 2000).ToList() };
        httpClient.SetLogResponse(DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));

        var result = await method.ResolveAsync(did);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
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
}
