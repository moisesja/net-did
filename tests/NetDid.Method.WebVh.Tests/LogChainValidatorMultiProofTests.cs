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
        string? created = null,
        string? expires = null,
        bool includeRawJson = false)
    {
        var vm = $"did:key:{keyPair.MultibasePublicKey}#{keyPair.MultibasePublicKey}";
        var proofOptions = new DataIntegrityProof
        {
            Cryptosuite = EddsaJcs2022Cryptosuite.CryptosuiteName,
            VerificationMethod = vm,
            Created = created,
            Expires = expires,
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
            ProofValue = proof.ProofValue!,
            RawJson = includeRawJson
                ? JsonSerializer.Serialize(proof, DataProofsJsonOptions.Default)
                : null
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
    // Interop: optional created, foreign proof members, round-trip
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

    [Fact]
    public async Task Issue101_ProofWithSignedExtraMember_Resolves()
    {
        // A conforming foreign proof may carry schema-permitted members NetDid does not
        // model (expires). eddsa-jcs-2022 signs the whole proof configuration, so the
        // verifier must reconstruct it from the wire bytes, not from a lossy model.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var foreignProof = await SignEntryAsync(
            entries[0], kpA,
            created: entries[0].Proof![0].Created,
            expires: "2099-12-31T23:59:59Z",
            includeRawJson: true);
        entries[0] = entries[0] with { Proof = [foreignProof] };

        var log = SerializeLog(entries);
        Encoding.UTF8.GetString(log).Should().Contain("\"expires\"");

        var result = await ResolveLogAsync(did, log);

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_Update_PreservesForeignProofMembers()
    {
        // Re-serializing a fetched log during update must not strip unmodeled proof
        // members — that would corrupt the foreign proof for every other resolver.
        var (kpA, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var foreignProof = await SignEntryAsync(
            entries[0], kpA,
            created: entries[0].Proof![0].Created,
            expires: "2099-12-31T23:59:59Z",
            includeRawJson: true);
        entries[0] = entries[0] with { Proof = [foreignProof] };
        var foreignLog = SerializeLog(entries);

        var (method, _) = CreateMethod();
        var updateResult = await method.UpdateAsync(did, new DidWebVhUpdateOptions
        {
            CurrentLogContent = foreignLog,
            SigningKey = signerA
        });

        var updatedJsonl = (string)updateResult.Artifacts![DidWebVhArtifacts.DidJsonl];
        updatedJsonl.Split('\n')[0].Should().Contain(foreignProof.RawJson!,
            "the genesis entry's foreign proof must round-trip byte-for-byte");

        // The republished log must still resolve.
        var (resolver, httpClient) = CreateMethod();
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(updatedJsonl));
        var resolved = await resolver.ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument.Should().NotBeNull();
    }

    // ================================================================
    // Proof-count resource cap (adversarial-review finding A)
    // ================================================================

    [Fact]
    public async Task Issue101_ProofCountAtCap_Resolves()
    {
        // A full array of valid, authorized proofs at the ceiling still resolves — the cap is
        // a resource guard, not a conformance rule, so it never rejects otherwise-valid logs.
        var (_, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var proof = entries[0].Proof![0];
        entries[0] = entries[0] with
        {
            Proof = Enumerable.Repeat(proof, LogChainValidator.MaxProofsPerEntry).ToList()
        };

        var result = await ResolveLogAsync(did, SerializeLog(entries));

        result.ResolutionMetadata.Error.Should().BeNull();
        result.DidDocument.Should().NotBeNull();
    }

    [Fact]
    public async Task Issue101_ProofCountAboveCap_ResolvesInvalidDidLog()
    {
        var (_, signerA) = CreateEd25519();
        var (did, entries, _) = await CreateLogAsync(signerA);

        var proof = entries[0].Proof![0];
        entries[0] = entries[0] with
        {
            Proof = Enumerable.Repeat(proof, LogChainValidator.MaxProofsPerEntry + 1).ToList()
        };

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
}
