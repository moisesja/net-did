using System.Globalization;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using NetCrypto;
using NetDid.Core.Model;
using NetDid.Method.WebVh.Model;

namespace NetDid.Method.WebVh.Tests;

[Collection("Culture-sensitive")]
public sealed class TimestampSecurityTests
{
    [Fact]
    public async Task CreateAndResolve_UseInvariantTimestampsAcrossCultures()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var signer = CreateEd25519Signer();
        string did;
        string logContent;
        string versionTime;

        using (new CultureScope("th-TH"))
        {
            var createResult = await method.CreateAsync(new DidWebVhCreateOptions
            {
                Domain = "example.com",
                UpdateKey = signer
            });

            did = createResult.Did.Value;
            logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

            using var log = JsonDocument.Parse(logContent);
            versionTime = log.RootElement.GetProperty("versionTime").GetString()!;
            var proofCreated = log.RootElement.GetProperty("proof")[0]
                .GetProperty("created").GetString();

            versionTime.Should().EndWith("Z");
            WebVhTimestamp.Parse(versionTime).Should().BeCloseTo(
                DateTimeOffset.UtcNow,
                TimeSpan.FromMinutes(1));
            proofCreated.Should().Be(versionTime);
        }

        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(logContent));

        using (new CultureScope("ar-SA"))
        {
            var exactResult = await method.ResolveAsync(did, new DidResolutionOptions
            {
                VersionTime = versionTime
            });
            var beforeCreationResult = await method.ResolveAsync(did, new DidResolutionOptions
            {
                VersionTime = "2000-01-01T00:00:00Z"
            });

            exactResult.DidDocument.Should().NotBeNull();
            beforeCreationResult.DidDocument.Should().BeNull();
            beforeCreationResult.ResolutionMetadata.Error.Should().Be("notFound");
        }
    }

    [Fact]
    public async Task Resolve_RejectsFractionalVersionTimeTampering()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var signer = CreateEd25519Signer();
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = signer
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        using var log = JsonDocument.Parse(logContent);
        var originalVersionTime = log.RootElement.GetProperty("versionTime").GetString()!;
        var tamperedVersionTime = WebVhTimestamp.Format(
            WebVhTimestamp.Parse(originalVersionTime).AddTicks(1));
        var tamperedLog = logContent.Replace(
            $"\"versionTime\":\"{originalVersionTime}\"",
            $"\"versionTime\":\"{tamperedVersionTime}\"",
            StringComparison.Ordinal);

        tamperedVersionTime.Should().NotBe(originalVersionTime);
        tamperedLog.Should().NotBe(logContent);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(tamperedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_RejectsEquivalentVersionTimeWireRewrite()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        using var log = JsonDocument.Parse(logContent);
        var original = log.RootElement.GetProperty("versionTime").GetString()!;
        var equivalent = original[..^1] + "+00:00";
        var tamperedLog = logContent.Replace(
            $"\"versionTime\":\"{original}\"",
            $"\"versionTime\":\"{equivalent}\"",
            StringComparison.Ordinal);

        WebVhTimestamp.Parse(equivalent).Should().Be(WebVhTimestamp.Parse(original));
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(tamperedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_NonUtcLogVersionTime_ReturnsInvalidDidLog()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        var logContent = (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl];

        using var log = JsonDocument.Parse(logContent);
        var original = log.RootElement.GetProperty("versionTime").GetString()!;
        var nonUtc = original[..^1] + "+02:00";
        var malformedLog = logContent.Replace(
            $"\"versionTime\":\"{original}\"",
            $"\"versionTime\":\"{nonUtc}\"",
            StringComparison.Ordinal);

        malformedLog.Should().NotBe(logContent);
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(malformedLog));

        var result = await method.ResolveAsync(did);

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("invalidDidLog");
    }

    [Fact]
    public async Task Resolve_InvalidVersionTimeQuery_DoesNotFallBackToLatest()
    {
        var httpClient = new MockWebVhHttpClient();
        var method = new DidWebVhMethod(httpClient);
        var createResult = await method.CreateAsync(new DidWebVhCreateOptions
        {
            Domain = "example.com",
            UpdateKey = CreateEd25519Signer()
        });
        var did = createResult.Did.Value;
        httpClient.SetLogResponse(
            DidUrlMapper.MapToLogUrl(did),
            Encoding.UTF8.GetBytes(
                (string)createResult.Artifacts![DidWebVhArtifacts.DidJsonl]));

        var result = await method.ResolveAsync(did, new DidResolutionOptions
        {
            VersionTime = "not-a-timestamp"
        });

        result.DidDocument.Should().BeNull();
        result.ResolutionMetadata.Error.Should().Be("notFound");
    }

    [Theory]
    [InlineData("2026-07-10T12:00:00")]
    [InlineData("2026-07-10 12:00:00Z")]
    [InlineData("2026-07-10T12:00:00+01:00")]
    public void TimestampParser_RejectsNonUtcOrNonCanonicalForms(string value)
    {
        WebVhTimestamp.TryParse(value, out _).Should().BeFalse();
        var act = () => WebVhTimestamp.Parse(value);
        act.Should().Throw<FormatException>();
    }

    [Fact]
    public void FindTargetIndex_UsesAuthenticatedFractionalPrecision()
    {
        var first = new DateTimeOffset(2026, 7, 10, 12, 0, 0, 100, TimeSpan.Zero);
        var second = new DateTimeOffset(2026, 7, 10, 12, 0, 0, 900, TimeSpan.Zero);
        var entries = new[]
        {
            CreateSelectionEntry("1-zFirst", first),
            CreateSelectionEntry("2-zSecond", second)
        };

        var selected = DidWebVhMethod.FindTargetIndex(entries, new DidResolutionOptions
        {
            VersionTime = "2026-07-10T12:00:00.5Z"
        });

        selected.Should().Be(0);
    }

    private static LogEntry CreateSelectionEntry(string versionId, DateTimeOffset versionTime)
        => new()
        {
            VersionId = versionId,
            VersionTime = versionTime,
            Parameters = new LogEntryParameters(),
            State = new DidDocument { Id = new Did("did:example:timestamp-selection") }
        };

    private static ISigner CreateEd25519Signer()
    {
        var keyPair = new DefaultKeyGenerator().Generate(KeyType.Ed25519);
        return new KeyPairSigner(keyPair, new DefaultCryptoProvider());
    }

    private sealed class CultureScope : IDisposable
    {
        private readonly CultureInfo _originalCulture = CultureInfo.CurrentCulture;
        private readonly CultureInfo _originalUiCulture = CultureInfo.CurrentUICulture;

        public CultureScope(string name)
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
        }

        public void Dispose()
        {
            CultureInfo.CurrentCulture = _originalCulture;
            CultureInfo.CurrentUICulture = _originalUiCulture;
        }
    }
}
