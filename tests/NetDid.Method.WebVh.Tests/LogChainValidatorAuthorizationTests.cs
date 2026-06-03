using System.Text;
using FluentAssertions;
using NetCid;
using NetDid.Core;
using NetDid.Core.Crypto;
using NetDid.Core.Crypto.DataIntegrity;
using NetDid.Core.Crypto.Jcs;
using NetDid.Core.Exceptions;
using NetDid.Method.WebVh;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Regression tests for issue #50: did:webvh proof authorization bypass.
///
/// Before the fix, <c>LogChainValidator.ValidateProof</c> authorized proofs
/// using <c>proof.VerificationMethod.Contains(authorizedKey)</c>, while the signature
/// was verified against the key extracted from the DID part only. An attacker could
/// craft <c>did:key:&lt;attacker&gt;#&lt;authorized&gt;</c> and sign with their own
/// key, passing both checks.
/// </summary>
public class LogChainValidatorAuthorizationTests
{
    private readonly DefaultKeyGenerator _keyGen = new();
    private readonly DefaultCryptoProvider _crypto = new();

    private (DidWebVhMethod Method, MockWebVhHttpClient HttpClient) CreateMethod()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient, _crypto);
        return (method, httpClient);
    }

    private (KeyPair KeyPair, ISigner Signer) CreateEd25519()
    {
        var keyPair = _keyGen.Generate(KeyType.Ed25519);
        return (keyPair, new KeyPairSigner(keyPair, _crypto));
    }

    /// <summary>
    /// Build a fresh did:webvh log signed by <paramref name="authorizedSigner"/>,
    /// then return the parsed entries so the test can tamper with the proof.
    /// </summary>
    private async Task<(string Did, List<LogEntry> Entries)> CreateLogAsync(ISigner authorizedSigner)
    {
        var (method, _) = CreateMethod();
        var result = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = authorizedSigner
        });

        var jsonl = (string)result.Artifacts!["did.jsonl"];
        var entries = LogEntrySerializer.ParseJsonLines(Encoding.UTF8.GetBytes(jsonl)).ToList();
        return (result.Did.Value, entries);
    }

    /// <summary>
    /// Re-sign the genesis entry over its canonicalized form (without proof) using
    /// <paramref name="signerKeyPair"/>'s private key, and return a copy whose proof's
    /// <c>verificationMethod</c> is <paramref name="verificationMethod"/>.
    /// </summary>
    private LogEntry TamperGenesisProof(
        LogEntry genesis, KeyPair signerKeyPair, string verificationMethod)
    {
        var entryJsonWithoutProof = LogEntrySerializer.SerializeWithoutProof(genesis);
        var canonical = JsonCanonicalization.CanonicalizeToUtf8(entryJsonWithoutProof);
        var signature = _crypto.Sign(KeyType.Ed25519, signerKeyPair.PrivateKey, canonical);
        var proofValue = Multibase.Encode(signature, MultibaseEncoding.Base58Btc);

        var original = genesis.Proof![0];
        return genesis with
        {
            Proof =
            [
                new DataIntegrityProofValue
                {
                    Type = original.Type,
                    Cryptosuite = original.Cryptosuite,
                    VerificationMethod = verificationMethod,
                    Created = original.Created,
                    ProofPurpose = original.ProofPurpose,
                    ProofValue = proofValue
                }
            ]
        };
    }

    private static byte[] SerializeLog(IEnumerable<LogEntry> entries)
        => LogEntrySerializer.ToJsonLines(entries.ToList());

    // ================================================================
    // Scenario 1: attacker key with authorized key in fragment → FAIL
    // ================================================================

    [Fact]
    public async Task Issue50_AttackerKeyWithAuthorizedFragment_FailsResolution()
    {
        var (authorizedKp, authorizedSigner) = CreateEd25519();
        var (attackerKp, _) = CreateEd25519();
        var (did, entries) = await CreateLogAsync(authorizedSigner);

        // Craft the exploit verificationMethod from the issue:
        // did:key:<attacker>#<authorized>
        var verificationMethod = $"did:key:{attackerKp.MultibasePublicKey}#{authorizedKp.MultibasePublicKey}";

        // Sign the entry with the attacker's private key so the signature verifies
        // against the key extracted from the DID part (the attacker's key).
        entries[0] = TamperGenesisProof(entries[0], attackerKp, verificationMethod);

        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));

        var resolveResult = await method.ResolveAsync(did);

        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().NotBeNull();
    }

    // ================================================================
    // Scenario 2: authorized key with matching fragment → PASS
    // (This is the normal/healthy path produced by CreateProofAsync.)
    // ================================================================

    [Fact]
    public async Task Issue50_AuthorizedKeyWithMatchingFragment_Resolves()
    {
        var (_, authorizedSigner) = CreateEd25519();
        var (did, entries) = await CreateLogAsync(authorizedSigner);

        // No tampering — verificationMethod is already "did:key:<auth>#<auth>".
        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));

        var resolveResult = await method.ResolveAsync(did);

        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.ResolutionMetadata.Error.Should().BeNull();
    }

    // ================================================================
    // Scenario 3: authorized key with no fragment → PASS
    // ================================================================

    [Fact]
    public async Task Issue50_AuthorizedKeyWithoutFragment_Resolves()
    {
        var (authorizedKp, authorizedSigner) = CreateEd25519();
        var (did, entries) = await CreateLogAsync(authorizedSigner);

        // Strip the fragment from the verificationMethod. The signature itself
        // is unchanged (signed by the authorized key), and the DID-part still
        // points at the same authorized multibase key.
        var stripped = $"did:key:{authorizedKp.MultibasePublicKey}";
        var original = entries[0].Proof![0];
        entries[0] = entries[0] with
        {
            Proof =
            [
                new DataIntegrityProofValue
                {
                    Type = original.Type,
                    Cryptosuite = original.Cryptosuite,
                    VerificationMethod = stripped,
                    Created = original.Created,
                    ProofPurpose = original.ProofPurpose,
                    ProofValue = original.ProofValue
                }
            ]
        };

        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));

        var resolveResult = await method.ResolveAsync(did);

        resolveResult.DidDocument.Should().NotBeNull();
        resolveResult.ResolutionMetadata.Error.Should().BeNull();
    }

    // ================================================================
    // Scenario 4: DID/fragment mismatch where DID is authorized,
    // fragment names a different (attacker) key → FAIL
    // ================================================================

    [Fact]
    public async Task Issue50_DidFragmentMismatch_FailsResolution()
    {
        var (authorizedKp, authorizedSigner) = CreateEd25519();
        var (attackerKp, _) = CreateEd25519();
        var (did, entries) = await CreateLogAsync(authorizedSigner);

        // DID part is the authorized key, fragment is the attacker key.
        // Signature is signed by authorized key (so it WOULD verify), but
        // the DID/fragment mismatch must cause authorization to reject the proof.
        var verificationMethod = $"did:key:{authorizedKp.MultibasePublicKey}#{attackerKp.MultibasePublicKey}";
        entries[0] = TamperGenesisProof(entries[0], authorizedKp, verificationMethod);

        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));

        var resolveResult = await method.ResolveAsync(did);

        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().NotBeNull();
    }

    // ================================================================
    // Scenario 5: authorized key as substring in extra path text → FAIL
    // ================================================================

    [Fact]
    public async Task Issue50_AuthorizedKeyInPathSegment_FailsResolution()
    {
        var (authorizedKp, authorizedSigner) = CreateEd25519();
        var (attackerKp, _) = CreateEd25519();
        var (did, entries) = await CreateLogAsync(authorizedSigner);

        // Place the authorized key in a path segment. The pre-fix substring match
        // would have accepted this; the new parser must reject any '/' or '?'.
        var verificationMethod = $"did:key:{attackerKp.MultibasePublicKey}/{authorizedKp.MultibasePublicKey}";
        entries[0] = TamperGenesisProof(entries[0], attackerKp, verificationMethod);

        var (method, httpClient) = CreateMethod();
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did), SerializeLog(entries));

        var resolveResult = await method.ResolveAsync(did);

        resolveResult.DidDocument.Should().BeNull();
        resolveResult.ResolutionMetadata.Error.Should().NotBeNull();
    }

    // ================================================================
    // Unit-level coverage for the new helper
    // ================================================================

    [Fact]
    public void ExtractDidKeyMultibase_MatchingFragment_ReturnsKey()
    {
        var (kp, _) = CreateEd25519();
        var vm = $"did:key:{kp.MultibasePublicKey}#{kp.MultibasePublicKey}";

        DataIntegrityProofEngine.ExtractDidKeyMultibase(vm)
            .Should().Be(kp.MultibasePublicKey);
    }

    [Fact]
    public void ExtractDidKeyMultibase_NoFragment_ReturnsKey()
    {
        var (kp, _) = CreateEd25519();
        var vm = $"did:key:{kp.MultibasePublicKey}";

        DataIntegrityProofEngine.ExtractDidKeyMultibase(vm)
            .Should().Be(kp.MultibasePublicKey);
    }

    [Fact]
    public void ExtractDidKeyMultibase_FragmentMismatch_ReturnsNull()
    {
        var (kp1, _) = CreateEd25519();
        var (kp2, _) = CreateEd25519();
        var vm = $"did:key:{kp1.MultibasePublicKey}#{kp2.MultibasePublicKey}";

        DataIntegrityProofEngine.ExtractDidKeyMultibase(vm).Should().BeNull();
    }

    [Fact]
    public void ExtractDidKeyMultibase_PathSegment_ReturnsNull()
    {
        var (kp, _) = CreateEd25519();
        var vm = $"did:key:{kp.MultibasePublicKey}/extra";

        DataIntegrityProofEngine.ExtractDidKeyMultibase(vm).Should().BeNull();
    }

    [Fact]
    public void ExtractDidKeyMultibase_QueryString_ReturnsNull()
    {
        var (kp, _) = CreateEd25519();
        var vm = $"did:key:{kp.MultibasePublicKey}?foo=bar";

        DataIntegrityProofEngine.ExtractDidKeyMultibase(vm).Should().BeNull();
    }

    [Fact]
    public void ExtractDidKeyMultibase_NonDidKey_ReturnsNull()
    {
        DataIntegrityProofEngine.ExtractDidKeyMultibase("did:web:example.com")
            .Should().BeNull();
    }
}
