using System.Text;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh;
using Xunit;

namespace NetDid.Method.WebVh.Tests;

/// <summary>
/// Upgrade guards for issue #110 (DataProofsDotnet 0.1.0-preview.1 → 1.1.1). A green build and
/// a green suite are not sufficient evidence for a dependency bump that crosses a major version
/// under the Data Integrity verification path, because the suite only proves this version can
/// verify what this version produced. These tests pin the properties that a version bump could
/// silently change:
///
///   • a proof produced by the OLD library still verifies (no wire-format drift);
///   • non-canonical base64url in a caller-supplied proof is still mapped to our error at the
///     trust boundary, not leaked as a raw FormatException (1.0.0 made Base64Url.Decode strict);
///   • the active cryptosuite set has not silently widened (1.0.0 added the Legacy
///     LD-Signature suites, deliberately unregistered by default).
/// </summary>
public class DataProofsUpgradeCompatibilityTests
{
    private static string FixturePath(string name)
        => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static (string Did, byte[] Log) LegacyFixture()
    {
        var did = File.ReadAllText(FixturePath("dataproofs-preview1-did.txt")).Trim();
        var log = File.ReadAllBytes(FixturePath("dataproofs-preview1-did.jsonl"));
        return (did, log);
    }

    /// <summary>
    /// The wire-drift oracle: this did.jsonl and its <c>eddsa-jcs-2022</c> proof were written by
    /// DataProofsDotnet 0.1.0-preview.1. A DID published by an earlier release of this library —
    /// or by any other conforming implementation — must keep resolving.
    /// </summary>
    [Fact]
    public async Task ProofWrittenByThePreUpgradeLibrary_StillVerifies()
    {
        var (did, log) = LegacyFixture();
        var http = new MockWebVhHttpClient();
        http.SetLogResponse(DidUrlMapper.MapToLogUrl(did), log);

        var resolved = await new DidWebVhMethod(http).ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().BeNull(
            "a proof created by the pre-upgrade library must still verify");
        resolved.DidDocument.Should().NotBeNull();
        resolved.DidDocument!.Id!.Value.Should().Be(did);
    }

    /// <summary>
    /// The fixture must not have drifted into something trivially self-satisfying: assert it
    /// really carries the suite and proof shape we think it does.
    /// </summary>
    [Fact]
    public void LegacyFixture_IsTheProofShapeUnderTest()
    {
        var (_, log) = LegacyFixture();
        var text = Encoding.UTF8.GetString(log);

        text.Should().Contain("\"cryptosuite\":\"eddsa-jcs-2022\"");
        text.Should().Contain("\"type\":\"DataIntegrityProof\"");
        text.Should().Contain("\"proofValue\":\"z");   // base58-btc multibase
        log.Take(3).Should().NotEqual([(byte)0xEF, (byte)0xBB, (byte)0xBF],
            "a real did.jsonl has no BOM");
    }

    /// <summary>
    /// 1.0.0 made <c>Base64Url.Decode</c> strict (padding / whitespace / standard-base64
    /// alphabet now throw <see cref="FormatException"/>). Whatever the library does internally,
    /// a malformed proof arriving from the network must still surface as our resolution error —
    /// never as a raw FormatException escaping <c>ResolveAsync</c>.
    /// </summary>
    [Theory]
    [InlineData("z5udp82yoCD3ds8tQ6rRZMUJjfcWExz5wf5118c9pBosfiaVBkUvKELCEdreQkMeBTekZPstEomFSbtpDxND8Vrh8",
                "u5udp82yoCD3ds8t")]              // base64url multibase prefix, truncated
    [InlineData("z5udp82yoCD3ds8tQ6rRZMUJjfcWExz5wf5118c9pBosfiaVBkUvKELCEdreQkMeBTekZPstEomFSbtpDxND8Vrh8",
                "uYWJjZA==")]                     // base64url WITH padding — strict now rejects
    [InlineData("z5udp82yoCD3ds8tQ6rRZMUJjfcWExz5wf5118c9pBosfiaVBkUvKELCEdreQkMeBTekZPstEomFSbtpDxND8Vrh8",
                "u YWJjZA")]                      // interior whitespace
    [InlineData("z5udp82yoCD3ds8tQ6rRZMUJjfcWExz5wf5118c9pBosfiaVBkUvKELCEdreQkMeBTekZPstEomFSbtpDxND8Vrh8",
                "uYWJj+2Q")]                      // standard-base64 '+'
    public async Task MalformedProofValue_MapsToAResolutionError_NotARawFault(
        string original, string replacement)
    {
        var (did, log) = LegacyFixture();
        var tampered = Encoding.UTF8.GetString(log).Replace(original, replacement);
        tampered.Should().NotBe(Encoding.UTF8.GetString(log), "the fixture substitution must apply");

        var http = new MockWebVhHttpClient();
        http.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(tampered));

        // Must not throw: the resolver's contract is to report errors, not leak faults.
        var resolved = await new DidWebVhMethod(http).ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().NotBeNull(
            "a malformed proofValue must be reported as a resolution error");
        resolved.DidDocument.Should().BeNull();
    }

    /// <summary>
    /// A tampered-but-well-formed proofValue must still fail verification (guards against the
    /// upgrade accidentally loosening dispatch so that a proof is skipped rather than checked).
    /// </summary>
    [Fact]
    public async Task TamperedProofValue_FailsVerification()
    {
        var (did, log) = LegacyFixture();
        var text = Encoding.UTF8.GetString(log);
        // Flip one character inside the base58 proofValue, preserving the multibase prefix.
        var original = "z5udp82yoCD3ds8t";
        var tampered = text.Replace(original, "z5udp82yoCD3ds8u");
        tampered.Should().NotBe(text);

        var http = new MockWebVhHttpClient();
        http.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(tampered));

        var resolved = await new DidWebVhMethod(http).ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().NotBeNull("a forged proof must not verify");
    }

    /// <summary>
    /// 1.0.0 shipped <c>DataProofsDotnet.Legacy</c> (Ed25519Signature2020,
    /// EcdsaSecp256r1Signature2019) and added type-based dispatch. Those suites are deliberately
    /// NOT in <c>CryptosuiteRegistry.CreateDefault()</c>; this pins that net-did has not silently
    /// widened what it will accept — a legacy-typed proof must be rejected, not verified.
    /// </summary>
    [Fact]
    public async Task LegacyLdSignatureProofType_IsNotAccepted()
    {
        var (did, log) = LegacyFixture();
        var tampered = Encoding.UTF8.GetString(log)
            .Replace("\"type\":\"DataIntegrityProof\"", "\"type\":\"Ed25519Signature2020\"");
        tampered.Should().NotBe(Encoding.UTF8.GetString(log));

        var http = new MockWebVhHttpClient();
        http.SetLogResponse(DidUrlMapper.MapToLogUrl(did), Encoding.UTF8.GetBytes(tampered));

        var resolved = await new DidWebVhMethod(http).ResolveAsync(did);

        resolved.ResolutionMetadata.Error.Should().NotBeNull(
            "did:webvh v1.0 secures entries with DataIntegrityProof; a legacy LD-Signature " +
            "type must not be accepted just because the dependency can now dispatch it");
    }

    /// <summary>
    /// Round-trip on the CURRENT library, so the upgrade is not merely backward-compatible but
    /// still produces proofs this stack verifies.
    /// </summary>
    [Fact]
    public async Task FreshlyCreatedProof_RoundTripsOnTheUpgradedLibrary()
    {
        var keyGen = new DefaultKeyGenerator();
        var crypto = new DefaultCryptoProvider();
        var http = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(http);

        using var key = keyGen.Generate(KeyType.Ed25519);
        using var signer = new KeyPairSigner(key, crypto, ownsKeyPair: false);

        var created = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain    = "example.com",
            UpdateKey = signer,
        });

        var log = (string)created.Artifacts!["did.jsonl"];
        http.SetLogResponse(
            DidUrlMapper.MapToLogUrl(created.Did.Value), Encoding.UTF8.GetBytes(log));

        var resolved = await method.ResolveAsync(created.Did.Value);

        resolved.ResolutionMetadata.Error.Should().BeNull();
        resolved.DidDocument!.Id!.Value.Should().Be(created.Did.Value);
    }
}
