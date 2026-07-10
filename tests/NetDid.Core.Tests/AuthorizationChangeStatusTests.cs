using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using NetCrypto;
using NetDid.Core;
using NetDid.Core.Model;

namespace NetDid.Core.Tests;

public class AuthorizationChangeStatusTests
{
    /// <summary>
    /// A method that performs an update but does NOT evaluate authorization-change evidence —
    /// standing in for any third-party <see cref="IDidMethod"/> implementation compiled without
    /// setting the new property. It must be indistinguishable, to a consumer, from "unknown".
    /// </summary>
    private sealed class NonReportingMethod : DidMethodBase
    {
        public override string MethodName => "example";
        public override DidMethodCapabilities Capabilities => DidMethodCapabilities.Update;
        public override IReadOnlyList<KeyType> SupportedKeyTypes { get; } = new List<KeyType>();

        protected override Task<DidCreateResult> CreateCoreAsync(DidCreateOptions options, CancellationToken ct)
            => throw new NotSupportedException();

        protected override Task<DidResolutionResult> ResolveCoreAsync(string did, DidResolutionOptions? options, CancellationToken ct)
            => throw new NotSupportedException();

        protected override Task<DidUpdateResult> UpdateCoreAsync(string did, DidUpdateOptions options, CancellationToken ct)
            => Task.FromResult(new DidUpdateResult { DidDocument = new DidDocument { Id = new Did(did) } });
    }

    private sealed record UpdateOptions : DidUpdateOptions;

    [Fact]
    public async Task Update_WhenMethodDoesNotReportEvidence_IsUnknown_NotUnchanged()
    {
        var method = new NonReportingMethod();

        var result = await method.UpdateAsync("did:example:123", new UpdateOptions());

        // Fail closed: "producer supplied no evidence" must NOT read as "confirmed document-only".
        result.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unknown);
        result.AuthorizationChange.Should().NotBe(AuthorizationChangeStatus.Unchanged);
    }

    [Fact]
    public void DidUpdateResult_Default_AuthorizationChange_IsUnknown()
    {
        var result = new DidUpdateResult { DidDocument = new DidDocument { Id = new Did("did:example:1") } };

        result.AuthorizationChange.Should().Be(AuthorizationChangeStatus.Unknown);
    }
}
