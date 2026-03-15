using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Core.Parsing;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.CoreProperties;

[Collection("W3C Conformance")]
public class VerificationMethodTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer", "did:webvh" };

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task VmHasRequiredProperties(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var allHaveRequired = doc.VerificationMethod?.All(vm =>
            vm.Id is not null && vm.Type is not null && vm.Controller.Value is not null) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-6",
            "VM has required properties (id, type, controller)", allHaveRequired);
        allHaveRequired.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task VmIdConformsToDidUrlSyntax(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var allValid = doc.VerificationMethod?.All(vm =>
            DidParser.ParseDidUrl(vm.Id) is not null) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-7",
            "VM id conforms to DID URL syntax", allValid);
        allValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task VmTypeIsNonEmptyString(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var allValid = doc.VerificationMethod?.All(vm =>
            !string.IsNullOrEmpty(vm.Type)) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-8",
            "VM type is non-empty string", allValid);
        allValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task VmControllerConformsToDIDSyntax(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var allValid = doc.VerificationMethod?.All(vm =>
            DidParser.IsValid(vm.Controller.Value)) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-9",
            "VM controller conforms to DID syntax", allValid);
        allValid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task VmHasExactlyOneKeyRepresentation(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var allHaveOne = doc.VerificationMethod?.All(vm =>
        {
            var count = 0;
            if (vm.PublicKeyMultibase is not null) count++;
            if (vm.PublicKeyJwk is not null) count++;
            if (vm.BlockchainAccountId is not null) count++;
            return count == 1;
        }) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-10",
            "VM has exactly one key representation", allHaveOne);
        allHaveOne.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task MultibaseKeyIsNonEmptyString(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var allValid = doc.VerificationMethod?
            .Where(vm => vm.PublicKeyMultibase is not null)
            .All(vm => vm.PublicKeyMultibase!.Length > 0 && vm.PublicKeyMultibase.StartsWith('z')) ?? true;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-11",
            "Multibase key is non-empty and starts with 'z'", allValid);
        allValid.Should().BeTrue();
    }

    [Fact]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task JwkDoesNotContainPrivateKeyMaterial()
    {
        var (_, doc) = await _factory.CreateDidKey(
            repr: VerificationMethodRepresentation.JsonWebKey2020);

        var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
        var noPrivateKey = !json.Contains("\"d\":");
        ConformanceReportSink.Record("did:key", "did-core-properties", "4", "4-12",
            "JWK does not contain private key material", noPrivateKey);
        noPrivateKey.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task VerificationMethodIdsAreUnique(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var ids = doc.VerificationMethod?.Select(vm => vm.Id).ToList() ?? [];
        var unique = ids.Distinct().Count() == ids.Count;
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-13",
            "Verification method IDs are unique", unique);
        unique.Should().BeTrue();
    }
}
