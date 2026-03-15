using FluentAssertions;
using NetDid.Core.Model;
using NetDid.Core.Parsing;
using NetDid.Tests.W3CConformance.Infrastructure;

namespace NetDid.Tests.W3CConformance.CoreProperties;

[Collection("W3C Conformance")]
public class VerificationRelationshipTests
{
    private readonly TestDidFactory _factory = new();

    public static TheoryData<string> AllMethods => new() { "did:key", "did:peer", "did:webvh" };

    private static bool ValidateRelationshipEntries(IReadOnlyList<VerificationRelationshipEntry>? entries)
    {
        if (entries is null) return true;
        return entries.All(entry =>
        {
            if (entry.IsReference)
                return DidParser.IsValidDidReference(entry.Reference!);
            if (entry.EmbeddedMethod is not null)
                return entry.EmbeddedMethod.Id is not null
                    && entry.EmbeddedMethod.Type is not null
                    && entry.EmbeddedMethod.Controller.Value is not null;
            return false;
        });
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task AuthenticationIsValidRelationship(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var valid = ValidateRelationshipEntries(doc.Authentication);
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-14",
            "authentication entries are valid references or embedded VMs", valid);
        valid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task AssertionMethodIsValidRelationship(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var valid = ValidateRelationshipEntries(doc.AssertionMethod);
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-15",
            "assertionMethod entries are valid references or embedded VMs", valid);
        valid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task KeyAgreementIsValidRelationship(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var valid = ValidateRelationshipEntries(doc.KeyAgreement);
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-16",
            "keyAgreement entries are valid references or embedded VMs", valid);
        valid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task CapabilityInvocationIsValidRelationship(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var valid = ValidateRelationshipEntries(doc.CapabilityInvocation);
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-17",
            "capabilityInvocation entries are valid references or embedded VMs", valid);
        valid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task CapabilityDelegationIsValidRelationship(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        var valid = ValidateRelationshipEntries(doc.CapabilityDelegation);
        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-18",
            "capabilityDelegation entries are valid references or embedded VMs", valid);
        valid.Should().BeTrue();
    }

    [Theory, MemberData(nameof(AllMethods))]
    [Trait("W3CCategory", "did-core-properties")]
    public async Task RelationshipReferencesResolveToExistingVm(string method)
    {
        var (_, doc) = await _factory.CreateDid(method);

        // Collect all VM IDs (top-level + embedded across all relationships)
        var allVmIds = new HashSet<string>();
        if (doc.VerificationMethod is not null)
            foreach (var vm in doc.VerificationMethod)
                allVmIds.Add(vm.Id);

        void CollectEmbedded(IReadOnlyList<VerificationRelationshipEntry>? entries)
        {
            if (entries is null) return;
            foreach (var e in entries)
                if (e.EmbeddedMethod is not null)
                    allVmIds.Add(e.EmbeddedMethod.Id);
        }

        CollectEmbedded(doc.Authentication);
        CollectEmbedded(doc.AssertionMethod);
        CollectEmbedded(doc.KeyAgreement);
        CollectEmbedded(doc.CapabilityInvocation);
        CollectEmbedded(doc.CapabilityDelegation);

        // Now check all references point to known VM IDs
        bool CheckRefs(IReadOnlyList<VerificationRelationshipEntry>? entries)
        {
            if (entries is null) return true;
            return entries.Where(e => e.IsReference).All(e => allVmIds.Contains(e.Reference!));
        }

        var allResolved = CheckRefs(doc.Authentication)
            && CheckRefs(doc.AssertionMethod)
            && CheckRefs(doc.KeyAgreement)
            && CheckRefs(doc.CapabilityInvocation)
            && CheckRefs(doc.CapabilityDelegation);

        ConformanceReportSink.Record(method, "did-core-properties", "4", "4-19",
            "Relationship references resolve to existing VMs", allResolved);
        allResolved.Should().BeTrue();
    }
}
