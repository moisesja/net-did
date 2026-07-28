using DotNet.Testcontainers.Builders;
using FluentAssertions;
using Xunit;

namespace NetDid.Method.Ethr.IntegrationTests;

#region Issue112 — opt-in gate honesty (env-var-only skip; fail loudly without Docker)

/// <summary>
/// Issue #112 — pins the gate's contract: the skip decision reads only
/// <c>NETDID_ETHR_INTEGRATION</c> (Docker never participates), and once opted in, an
/// unreachable Docker daemon maps to one actionable failure instead of raw Testcontainers
/// stack traces. Always-run plain facts. Gate values are supplied through the attribute's
/// internal test-seam constructor, so no test mutates process environment — mutation could
/// race fixture initialization under runner configs that re-enable collection parallelism.
/// </summary>
public class Issue112GateTests
{
    [Fact]
    public void Issue112_GateSkipsWhenVariableUnset()
    {
        new EthrIntegrationFactAttribute(null).Skip.Should().Contain("NETDID_ETHR_INTEGRATION=1",
            "the skip message must tell the reader how to opt in");
    }

    [Theory]
    [InlineData("")]
    [InlineData("true")]
    [InlineData("0")]
    [InlineData(" 1")]
    [InlineData("01")]
    public void Issue112_GateSkipsWhenVariableIsNotExactlyOne(string value)
    {
        new EthrIntegrationFactAttribute(value).Skip.Should().NotBeNull(
            "only the exact value \"1\" opts in");
    }

    [Fact]
    public void Issue112_GateActivatesWhenVariableIsOne()
    {
        new EthrIntegrationFactAttribute("1").Skip.Should().BeNull(
            "the gate reads only the environment variable — Docker plays no part in the skip decision");
    }

    [Fact]
    public void Issue112_PublicConstructorReadsTheEnvironmentVariable()
    {
        var ambient = Environment.GetEnvironmentVariable("NETDID_ETHR_INTEGRATION");

        new EthrIntegrationFactAttribute().Skip.Should().Be(new EthrIntegrationFactAttribute(ambient).Skip,
            "the public constructor must delegate the skip decision to the ambient variable value, " +
            "so this holds in default and opted-in runs alike");
    }

    [Fact]
    public void Issue112_DockerUnreachableFailureIsActionable()
    {
        var docker = new DockerUnavailableException(
            "Docker is either not running or misconfigured. " +
            "Details: Failed to connect to Docker endpoint at 'unix:///var/run/docker.sock'.",
            new AggregateException(
                new HttpRequestException("HTTP ping failed",
                    new IOException("Permission denied on /var/run/docker.sock"))));

        var failure = AnvilFixture.DockerUnreachableFailure(docker);

        failure.Message.Should().Contain("NETDID_ETHR_INTEGRATION=1 is set",
            "the failure must name the variable that opted the run in");
        failure.Message.Should().Contain("fails rather than skips",
            "opting in requests coverage, so a green run must never hide a suite that did not execute");
        failure.Message.Should().Contain("Start Docker (or unset NETDID_ETHR_INTEGRATION)",
            "the failure must state both remedies");
        failure.Message.Should().Contain("unix:///var/run/docker.sock",
            "Testcontainers' endpoint list is the actionable core of its message and must survive");
        failure.Message.Should().Contain("HttpRequestException: HTTP ping failed",
            "intermediate causes must survive as text");
        failure.Message.Should().Contain("IOException: Permission denied on /var/run/docker.sock",
            "the innermost reason distinguishes 'daemon stopped' from misconfiguration, where " +
            "'Start Docker' would be the wrong remedy");
        failure.InnerException.Should().BeNull(
            "the deep Testcontainers stacks are the noise this failure replaces; causes travel as text");
    }

    [Fact]
    public async Task Issue112_StartHelperMapsDockerUnavailabilityToTheActionableFailure()
    {
        var act = () => AnvilFixture.StartWithHonestDockerFailureAsync(
            () => throw new DockerUnavailableException("no usable Docker endpoint"));

        (await act.Should().ThrowAsync<InvalidOperationException>(
                "fixture startup must route Docker unavailability through the actionable failure"))
            .WithMessage("*NETDID_ETHR_INTEGRATION=1 is set*no usable Docker endpoint*");
    }

    [Fact]
    public async Task Issue112_StartHelperLeavesOtherStartupFailuresUntouched()
    {
        var act = () => AnvilFixture.StartWithHonestDockerFailureAsync(
            () => throw new TimeoutException("wait strategy timed out"));

        (await act.Should().ThrowAsync<TimeoutException>(
                "an image-pull or wait-strategy failure is not 'Docker unreachable' and must not be " +
                "relabeled — a wrong diagnosis sends the reader to the wrong remedy"))
            .WithMessage("wait strategy timed out");
    }
}

#endregion
