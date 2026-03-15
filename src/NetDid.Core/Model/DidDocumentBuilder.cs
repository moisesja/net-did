using Microsoft.IdentityModel.Tokens;

namespace NetDid.Core.Model;

/// <summary>
/// Fluent builder for constructing <see cref="DidDocument"/> instances.
/// Auto-sets controller to the document id when not explicitly specified.
/// </summary>
public sealed class DidDocumentBuilder
{
    private readonly Did _id;
    private readonly List<VerificationMethod> _verificationMethods = [];
    private readonly List<VerificationRelationshipEntry> _authentication = [];
    private readonly List<VerificationRelationshipEntry> _assertionMethod = [];
    private readonly List<VerificationRelationshipEntry> _keyAgreement = [];
    private readonly List<VerificationRelationshipEntry> _capabilityInvocation = [];
    private readonly List<VerificationRelationshipEntry> _capabilityDelegation = [];
    private readonly List<Service> _services = [];
    private readonly List<string> _alsoKnownAs = [];
    private IReadOnlyList<Did>? _controller;

    public DidDocumentBuilder(string did)
    {
        _id = new Did(did);
    }

    public DidDocumentBuilder(Did did)
    {
        _id = did;
    }

    public DidDocumentBuilder WithController(params Did[] controllers)
    {
        _controller = controllers;
        return this;
    }

    public DidDocumentBuilder AddAlsoKnownAs(string alias)
    {
        _alsoKnownAs.Add(alias);
        return this;
    }

    public DidDocumentBuilder AddVerificationMethod(Action<VerificationMethodBuilder> configure)
    {
        var builder = new VerificationMethodBuilder(_id);
        configure(builder);
        _verificationMethods.Add(builder.Build());
        return this;
    }

    public DidDocumentBuilder AddAuthentication(string reference)
    {
        _authentication.Add(VerificationRelationshipEntry.FromReference(reference));
        return this;
    }

    public DidDocumentBuilder AddAuthentication(Action<VerificationMethodBuilder> configure)
    {
        var builder = new VerificationMethodBuilder(_id);
        configure(builder);
        _authentication.Add(VerificationRelationshipEntry.FromEmbedded(builder.Build()));
        return this;
    }

    public DidDocumentBuilder AddAssertionMethod(string reference)
    {
        _assertionMethod.Add(VerificationRelationshipEntry.FromReference(reference));
        return this;
    }

    public DidDocumentBuilder AddAssertionMethod(Action<VerificationMethodBuilder> configure)
    {
        var builder = new VerificationMethodBuilder(_id);
        configure(builder);
        _assertionMethod.Add(VerificationRelationshipEntry.FromEmbedded(builder.Build()));
        return this;
    }

    public DidDocumentBuilder AddKeyAgreement(string reference)
    {
        _keyAgreement.Add(VerificationRelationshipEntry.FromReference(reference));
        return this;
    }

    public DidDocumentBuilder AddKeyAgreement(Action<VerificationMethodBuilder> configure)
    {
        var builder = new VerificationMethodBuilder(_id);
        configure(builder);
        _keyAgreement.Add(VerificationRelationshipEntry.FromEmbedded(builder.Build()));
        return this;
    }

    public DidDocumentBuilder AddCapabilityInvocation(string reference)
    {
        _capabilityInvocation.Add(VerificationRelationshipEntry.FromReference(reference));
        return this;
    }

    public DidDocumentBuilder AddCapabilityInvocation(Action<VerificationMethodBuilder> configure)
    {
        var builder = new VerificationMethodBuilder(_id);
        configure(builder);
        _capabilityInvocation.Add(VerificationRelationshipEntry.FromEmbedded(builder.Build()));
        return this;
    }

    public DidDocumentBuilder AddCapabilityDelegation(string reference)
    {
        _capabilityDelegation.Add(VerificationRelationshipEntry.FromReference(reference));
        return this;
    }

    public DidDocumentBuilder AddCapabilityDelegation(Action<VerificationMethodBuilder> configure)
    {
        var builder = new VerificationMethodBuilder(_id);
        configure(builder);
        _capabilityDelegation.Add(VerificationRelationshipEntry.FromEmbedded(builder.Build()));
        return this;
    }

    public DidDocumentBuilder AddService(Action<ServiceBuilder> configure)
    {
        var builder = new ServiceBuilder();
        configure(builder);
        _services.Add(builder.Build());
        return this;
    }

    public DidDocument Build()
    {
        return new DidDocument
        {
            Id = _id,
            Controller = _controller ?? [_id],
            AlsoKnownAs = _alsoKnownAs.Count > 0 ? _alsoKnownAs : null,
            VerificationMethod = _verificationMethods.Count > 0 ? _verificationMethods : null,
            Authentication = _authentication.Count > 0 ? _authentication : null,
            AssertionMethod = _assertionMethod.Count > 0 ? _assertionMethod : null,
            KeyAgreement = _keyAgreement.Count > 0 ? _keyAgreement : null,
            CapabilityInvocation = _capabilityInvocation.Count > 0 ? _capabilityInvocation : null,
            CapabilityDelegation = _capabilityDelegation.Count > 0 ? _capabilityDelegation : null,
            Service = _services.Count > 0 ? _services : null
        };
    }
}

/// <summary>
/// Fluent builder for <see cref="VerificationMethod"/>.
/// </summary>
public sealed class VerificationMethodBuilder
{
    private readonly Did _documentId;
    private string? _id;
    private string? _type;
    private Did? _controller;
    private string? _publicKeyMultibase;
    private JsonWebKey? _publicKeyJwk;

    internal VerificationMethodBuilder(Did documentId)
    {
        _documentId = documentId;
    }

    public VerificationMethodBuilder WithId(string id)
    {
        _id = id;
        return this;
    }

    public VerificationMethodBuilder WithType(string type)
    {
        _type = type;
        return this;
    }

    public VerificationMethodBuilder WithController(Did controller)
    {
        _controller = controller;
        return this;
    }

    public VerificationMethodBuilder WithMultibasePublicKey(string multibase)
    {
        _publicKeyMultibase = multibase;
        return this;
    }

    public VerificationMethodBuilder WithPublicKeyJwk(JsonWebKey jwk)
    {
        _publicKeyJwk = jwk;
        return this;
    }

    internal VerificationMethod Build()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(_id, nameof(_id));
        ArgumentException.ThrowIfNullOrWhiteSpace(_type, nameof(_type));

        return new VerificationMethod
        {
            Id = _id,
            Type = _type,
            Controller = _controller ?? _documentId,
            PublicKeyMultibase = _publicKeyMultibase,
            PublicKeyJwk = _publicKeyJwk
        };
    }
}

/// <summary>
/// Fluent builder for <see cref="Service"/>.
/// </summary>
public sealed class ServiceBuilder
{
    private string? _id;
    private string? _type;
    private ServiceEndpointValue? _endpoint;

    public ServiceBuilder WithId(string id)
    {
        _id = id;
        return this;
    }

    public ServiceBuilder WithType(string type)
    {
        _type = type;
        return this;
    }

    public ServiceBuilder WithEndpoint(string uri)
    {
        _endpoint = ServiceEndpointValue.FromUri(uri);
        return this;
    }

    public ServiceBuilder WithEndpoint(ServiceEndpointValue endpoint)
    {
        _endpoint = endpoint;
        return this;
    }

    internal Service Build()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(_id, nameof(_id));
        ArgumentException.ThrowIfNullOrWhiteSpace(_type, nameof(_type));
        ArgumentNullException.ThrowIfNull(_endpoint, nameof(_endpoint));

        return new Service
        {
            Id = _id,
            Type = _type,
            ServiceEndpoint = _endpoint
        };
    }
}
