using System.Reflection;
using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using NetDid.Core;
using NetDid.Extensions.DependencyInjection;
using NetDid.Method.WebVh;

namespace NetDid.Extensions.DependencyInjection.Tests;

/// <summary>
/// Fail-first public configuration contracts from the PR #143 round-three review.
/// Reflection keeps this test assembly compilable until the additive DI overload exists.
/// </summary>
public class Issue135ReviewRound3RegistrationTests
{
    [Fact]
    public void Issue135_R3_AddDidWebVh_ExposesBothVerificationBudgets()
    {
        FindBothBudgetsOverload().Should().NotBeNull(
            "DI consumers need the same witness-verification budget control as direct consumers");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Issue135_R3_AddDidWebVh_InvalidWitnessBudget_UsesPublicParameterName(
        int invalidBudget)
    {
        var overload = FindBothBudgetsOverload();
        overload.Should().NotBeNull(
            "the additive three-parameter AddDidWebVh overload must exist before its contract can be exercised");

        var services = new ServiceCollection();
        NetDidBuilder? builder = null;
        services.AddNetDid(value => builder = value);

        var act = () => overload!.Invoke(builder,
        [
            null,
            DidWebVhMethod.DefaultMaxControllerProofsPerEntry,
            invalidBudget
        ]);

        var invocation = act.Should().Throw<TargetInvocationException>().Which;
        invocation.InnerException.Should().BeOfType<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be("maxWitnessProofVerifications");
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Issue135_R3_DirectConstructor_InvalidWitnessBudget_UsesPublicParameterName(
        int invalidBudget)
    {
        var act = () => new DidWebVhMethod(
            new NullWebVhHttpClient(),
            logger: null,
            maxControllerProofsPerEntry: DidWebVhMethod.DefaultMaxControllerProofsPerEntry,
            maxWitnessProofVerifications: invalidBudget);

        act.Should().Throw<ArgumentOutOfRangeException>()
            .Which.ParamName.Should().Be("maxWitnessProofVerifications");
    }

    [Fact]
    public void Issue135_R3_AddDidWebVh_PropagatesCustomWitnessBudgetToResolvedMethod()
    {
        const int customBudget = 37;
        var services = new ServiceCollection();
        services.AddNetDid(builder => builder.AddDidWebVh(
            httpClientOptions: null,
            maxControllerProofsPerEntry: DidWebVhMethod.DefaultMaxControllerProofsPerEntry,
            maxWitnessProofVerifications: customBudget));
        using var provider = services.BuildServiceProvider();
        var method = provider.GetServices<IDidMethod>().Should().ContainSingle()
            .Which.Should().BeOfType<DidWebVhMethod>().Subject;
        var validator = typeof(DidWebVhMethod)
            .GetField("_witnessValidator", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(method)!;
        var actualBudget = (int)validator.GetType()
            .GetField("_maxProofVerifications", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(validator)!;

        actualBudget.Should().Be(customBudget,
            "the public DI overload must propagate its witness budget into the resolved method");
    }

    private static MethodInfo? FindBothBudgetsOverload() =>
        typeof(NetDidBuilder).GetMethod(
            nameof(NetDidBuilder.AddDidWebVh),
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            types:
            [
                typeof(WebVhHttpClientOptions),
                typeof(int),
                typeof(int)
            ],
            modifiers: null);

    private sealed class NullWebVhHttpClient : IWebVhHttpClient
    {
        public Task<byte[]?> FetchDidLogAsync(Uri logUrl, CancellationToken ct = default) =>
            Task.FromResult<byte[]?>(null);

        public Task<byte[]?> FetchWitnessFileAsync(Uri witnessUrl, CancellationToken ct = default) =>
            Task.FromResult<byte[]?>(null);
    }
}
