using System.Text.Json;
using FluentAssertions;
using NetDid.Core.Model;

namespace NetDid.Core.Tests.Model;

public class ServiceEndpointValueTests
{
    [Fact]
    public void FromUri_CreatesUriVariant()
    {
        var value = ServiceEndpointValue.FromUri("https://example.com");

        value.IsUri.Should().BeTrue();
        value.IsMap.Should().BeFalse();
        value.IsSet.Should().BeFalse();
        value.Uri.Should().Be("https://example.com");
    }

    [Fact]
    public void FromMap_CreatesMapVariant()
    {
        var map = new Dictionary<string, JsonElement>
        {
            ["key"] = JsonDocument.Parse("\"value\"").RootElement
        };
        var value = ServiceEndpointValue.FromMap(map);

        value.IsUri.Should().BeFalse();
        value.IsMap.Should().BeTrue();
        value.IsSet.Should().BeFalse();
    }

    [Fact]
    public void FromSet_CreatesSetVariant()
    {
        var set = new List<ServiceEndpointValue>
        {
            ServiceEndpointValue.FromUri("https://example.com"),
            ServiceEndpointValue.FromUri("https://example.org")
        };
        var value = ServiceEndpointValue.FromSet(set);

        value.IsUri.Should().BeFalse();
        value.IsMap.Should().BeFalse();
        value.IsSet.Should().BeTrue();
        value.Set.Should().HaveCount(2);
    }

    [Fact]
    public void FromSet_EmptyList_ThrowsArgumentException()
    {
        var act = () => ServiceEndpointValue.FromSet(new List<ServiceEndpointValue>());
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void FromUri_NullOrEmpty_ThrowsArgumentException()
    {
        var act = () => ServiceEndpointValue.FromUri("");
        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void ImplicitConversionFromString_CreatesUriVariant()
    {
        ServiceEndpointValue value = "https://example.com";
        value.IsUri.Should().BeTrue();
        value.Uri.Should().Be("https://example.com");
    }
}
