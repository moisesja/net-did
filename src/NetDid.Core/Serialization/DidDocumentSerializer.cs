using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Unicode;
using Microsoft.IdentityModel.Tokens;
using NetDid.Core.Model;
using NetDid.Core.Parsing;

namespace NetDid.Core.Serialization;

/// <summary>
/// Serializes and deserializes DID Documents per W3C DID Core §6 production/consumption rules.
/// </summary>
public static class DidDocumentSerializer
{
    private static readonly JsonSerializerOptions DefaultOptions = CreateOptions();
    private static readonly (string Type, string Context)[] ExactVerificationMethodContexts =
    [
        ("Multikey", "https://w3id.org/security/multikey/v1"),
        ("JsonWebKey2020", "https://w3id.org/security/suites/jws-2020/v1"),
    ];

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            WriteIndented = false
        };
        options.Converters.Add(new DidDocumentJsonConverter());
        options.Converters.Add(new DidDocumentDeserializerConverter());
        options.Converters.Add(new VerificationMethodJsonConverter());
        options.Converters.Add(new ServiceJsonConverter());
        options.Converters.Add(new ServiceEndpointValueJsonConverter());
        options.Converters.Add(new VerificationRelationshipEntryJsonConverter());
        return options;
    }

    /// <summary>
    /// Produce the DID Document as a JSON string in the specified representation.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// A verification method (top-level or embedded) omits the required <c>controller</c>
    /// (W3C DID Core §5.2). A resolved DID document must state it explicitly. Also thrown when a
    /// string to be written holds an unpaired UTF-16 surrogate, which the JSON writer would
    /// otherwise replace with U+FFFD.
    /// </exception>
    public static string Serialize(DidDocument doc, string contentType = DidContentTypes.JsonLd,
        JsonSerializerOptions? options = null)
    {
        var snapshot = SnapshotForSerialization(doc);
        RequireVerificationMethodControllersForProduction(snapshot);
        return SerializeCore(snapshot, contentType, options);
    }

    /// <summary>
    /// Produce the DID Document as UTF-8 bytes.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// A verification method (top-level or embedded) omits the required <c>controller</c>
    /// (W3C DID Core §5.2). A resolved DID document must state it explicitly. Also thrown when a
    /// string to be written holds an unpaired UTF-16 surrogate, which the JSON writer would
    /// otherwise replace with U+FFFD.
    /// </exception>
    public static byte[] SerializeToUtf8(DidDocument doc, string contentType = DidContentTypes.JsonLd,
        JsonSerializerOptions? options = null)
    {
        var snapshot = SnapshotForSerialization(doc);
        RequireVerificationMethodControllersForProduction(snapshot);
        return SerializeToUtf8Core(snapshot, contentType, options);
    }

    /// <summary>
    /// Method-internal producer check (issue #145): the same rules Serialize enforces before
    /// writing (null entries, DID Core id and URI syntax, unique service ids, verification-method
    /// controllers), for a method that builds a document without serializing it (did:peer:2),
    /// so it never creates or resolves a document that NetDid could not serialize.
    /// </summary>
    internal static void ValidateForProduction(DidDocument doc)
        => RequireVerificationMethodControllersForProduction(SnapshotForSerialization(doc));

    /// <summary>
    /// Produce a DID document that MAY contain verification methods without a <c>controller</c>.
    /// Method-internal counterpart to <see cref="DeserializeAllowingIncompleteVerificationMethods"/>,
    /// used only for did:peer:4's pre-contextualization template (its controllers are derived from
    /// the DID at resolution time). Never expose this on a public production path.
    /// </summary>
    internal static string SerializeAllowingIncompleteVerificationMethods(
        DidDocument doc, string contentType = DidContentTypes.JsonLd)
        => SerializeCore(SnapshotForSerialization(doc), contentType, options: null);

    /// <summary>
    /// Document-level member names that have a modeled representation. They must never appear in
    /// <see cref="DidDocument.AdditionalProperties"/> (deserialization already excludes them), and
    /// are rejected on serialization so a caller cannot inject e.g. a raw controllerless
    /// <c>verificationMethod</c> array past the modeled-controller validation (issue #121 review).
    /// </summary>
    private static readonly HashSet<string> ReservedDocumentMemberNames = new(StringComparer.Ordinal)
    {
        "@context", "id", "alsoKnownAs", "controller", "verificationMethod",
        "authentication", "assertionMethod", "keyAgreement",
        "capabilityInvocation", "capabilityDelegation", "service"
    };

    // Snapshot the caller's document ONCE at the production trust boundary. Every field that is a
    // caller-supplied interface-typed collection is materialized into a private frozen copy, so
    // controller validation, @context computation, and emission all read identical data — a hostile
    // implementation (or concurrent mutation) cannot return one set of verification methods to the
    // validator and another to the writer (repo trust-boundary rule; issue #121 review). Reserved
    // member names in AdditionalProperties are rejected here, before anything is written.
    private static DidDocument SnapshotForSerialization(DidDocument doc)
    {
        ArgumentNullException.ThrowIfNull(doc);

        Dictionary<string, JsonElement>? additional = null;
        if (doc.AdditionalProperties is not null)
        {
            additional = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
            foreach (var (key, val) in doc.AdditionalProperties)
            {
                if (ReservedDocumentMemberNames.Contains(key))
                    throw new ArgumentException(
                        $"AdditionalProperties contains the reserved DID document member '{key}', which " +
                        "has a modeled representation and must not be supplied as an extension property.",
                        nameof(doc));
                // A custom-comparer dictionary can hold two keys with the same text; the copy
                // must not silently keep only one of them (issue #145).
                if (!additional.TryAdd(key, val))
                    throw new ArgumentException(
                        "AdditionalProperties contains a duplicate member name.", nameof(doc));
            }
        }

        var snapshot = doc with
        {
            AlsoKnownAs = doc.AlsoKnownAs?.ToArray(),
            Controller = doc.Controller?.ToArray(),
            VerificationMethod = NoNullEntries(doc.VerificationMethod, "verificationMethod"),
            Authentication = NoNullEntries(doc.Authentication, "authentication"),
            AssertionMethod = NoNullEntries(doc.AssertionMethod, "assertionMethod"),
            KeyAgreement = NoNullEntries(doc.KeyAgreement, "keyAgreement"),
            CapabilityInvocation = NoNullEntries(doc.CapabilityInvocation, "capabilityInvocation"),
            CapabilityDelegation = NoNullEntries(doc.CapabilityDelegation, "capabilityDelegation"),
            Service = NoNullEntries(doc.Service, "service"),
            Context = doc.Context?.ToArray(),
            AdditionalProperties = additional
        };
        ValidateIdentifiers(snapshot, message => new ArgumentException(message, nameof(doc)));
        return snapshot;
    }

    // DID Core id and URI syntax, checked on consumption (JsonException) and production
    // (ArgumentException) so NetDid never accepts or emits what the other side rejects (issue #145):
    // §5.2 a verification method id, and a relationship reference, is a DID URL; §5.4 a service id
    // is a URI (or a relative "#fragment"), service ids are unique ("A conforming producer MUST NOT
    // produce multiple service entries with the same id"; "A conforming consumer MUST produce an
    // error if it detects multiple service entries with the same id"), and endpoint strings are
    // URIs; §5.1.3 alsoKnownAs entries are URIs. Messages are fixed text.
    private static void ValidateIdentifiers(DidDocument doc, Func<string, Exception> error)
    {
        if (doc.AlsoKnownAs is not null)
        {
            foreach (var alias in doc.AlsoKnownAs)
            {
                if (!DidParser.IsAbsoluteUri(alias))
                    throw error("Every 'alsoKnownAs' entry must be an RFC 3986 URI (W3C DID Core §5.1.3).");
            }
        }

        // A DID URL, a relative "#fragment", or NetDid's bare-id shorthand for "#id" (issue #136).
        static bool IsReference(string? id)
            => id is not null && (DidParser.IsValidDidReference(id) || DidParser.IsBareShorthand(id));

        void RequireMethodId(VerificationMethod? vm)
        {
            if (vm is null || !IsReference(vm.Id))
                throw error("A verification method id must be a DID URL (W3C DID Core §5.2).");
        }

        if (doc.VerificationMethod is not null)
            foreach (var vm in doc.VerificationMethod)
                RequireMethodId(vm);

        foreach (var relationship in new[]
                 {
                     doc.Authentication, doc.AssertionMethod, doc.KeyAgreement,
                     doc.CapabilityInvocation, doc.CapabilityDelegation
                 })
        {
            if (relationship is null)
                continue;
            foreach (var entry in relationship)
            {
                if (entry is null)
                    throw error("A verification relationship contains a null entry.");
                if (entry.IsReference)
                {
                    if (!IsReference(entry.Reference))
                        throw error("A verification relationship reference must be a DID URL (W3C DID Core §5.3).");
                }
                else
                {
                    RequireMethodId(entry.EmbeddedMethod);
                }
            }
        }

        if (doc.Service is null)
            return;

        var serviceIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var service in doc.Service)
        {
            if (service is null)
                throw error("'service' contains a null entry.");
            if (!IsReference(service.Id) && !DidParser.IsAbsoluteUri(service.Id))
                throw error("A service id must be an RFC 3986 URI (W3C DID Core §5.4).");

            // "x", "#x" and "<did>#x" name the same service: compare with the dereferencer's
            // own normalization, so the two can never disagree about which spellings collide.
            // It costs what the id costs, never the DID's length per service.
            if (!serviceIds.Add(DidParser.ComparableId(service.Id, doc.Id.Value)))
                throw error("Two services have the same id (W3C DID Core §5.4).");

            RequireEndpointUris(service.ServiceEndpoint, error);
        }
    }

    private static void RequireEndpointUris(ServiceEndpointValue? endpoint, Func<string, Exception> error)
    {
        if (endpoint is null)
            throw error("A service's serviceEndpoint is required (W3C DID Core §5.4).");
        if (endpoint.IsUri && !DidParser.IsAbsoluteUri(endpoint.Uri))
            throw error("A serviceEndpoint string must be an RFC 3986 URI (W3C DID Core §5.4).");
        if (endpoint.IsSet)
            foreach (var item in endpoint.Set!)
                RequireEndpointUris(item, error);
    }

    // The reader rejects a null verificationMethod, service or relationship entry, so the writer
    // must not emit one either (it crashed with NullReferenceException; issue #145).
    private static T[]? NoNullEntries<T>(IReadOnlyList<T>? entries, string member) where T : class
    {
        var copy = entries?.ToArray();
        if (copy is not null && Array.IndexOf(copy, null) >= 0)
            throw new ArgumentException($"'{member}' contains a null entry.", "doc");
        return copy;
    }

    private static string SerializeCore(DidDocument doc, string contentType, JsonSerializerOptions? options)
    {
        var wrapper = new SerializationContext(doc, contentType);
        return JsonSerializer.Serialize(wrapper, EffectiveOptions(options));
    }

    private static byte[] SerializeToUtf8Core(DidDocument doc, string contentType, JsonSerializerOptions? options)
    {
        var wrapper = new SerializationContext(doc, contentType);
        return JsonSerializer.SerializeToUtf8Bytes(wrapper, EffectiveOptions(options));
    }

    // Caller options are honored for formatting (WriteIndented, Encoder, ...), but NetDid's
    // converters always come first: they are internal, so caller options alone serialized the
    // internal wrapper by reflection, with no production rules and no UTF-16 checks (issue #145).
    // One copy per caller instance, so System.Text.Json metadata is not rebuilt on every call.
    private static readonly ConditionalWeakTable<JsonSerializerOptions, JsonSerializerOptions>
        CallerOptions = new();

    private static JsonSerializerOptions EffectiveOptions(JsonSerializerOptions? options)
        => options is null
            ? DefaultOptions
            : CallerOptions.GetValue(options, static caller =>
            {
                // Lock the caller's instance on first use, as System.Text.Json itself does, so a
                // later change is an error rather than silently ignored by this cache.
                caller.MakeReadOnly(populateMissingResolver: true);
                var effective = new JsonSerializerOptions(caller)
                {
                    // A caller resolver could describe NetDid's internal types itself (bypassing
                    // the converters) or fail to describe them at all.
                    TypeInfoResolver = new System.Text.Json.Serialization.Metadata.DefaultJsonTypeInfoResolver()
                };
                var converters = DefaultOptions.Converters;
                for (var i = converters.Count - 1; i >= 0; i--)
                    effective.Converters.Insert(0, converters[i]);
                return effective;
            });

    private static readonly JsonDocumentOptions RejectDuplicatesOptions =
        new() { AllowDuplicateProperties = false };

    /// <summary>
    /// Consume (deserialize) a DID Document from JSON.
    /// </summary>
    /// <exception cref="JsonException">
    /// The input is malformed: for example a duplicate member, an unpaired surrogate (escaped or
    /// raw), or a missing or non-string verification-method controller.
    /// </exception>
    /// <exception cref="NetDid.Core.Exceptions.InvalidDidException">A DID-valued member is not a syntactically valid DID.</exception>
    public static DidDocument Deserialize(string json, string? contentType = null)
    {
        RejectMalformedJson(json);
        try
        {
            var doc = JsonSerializer.Deserialize<DidDocument>(json, DefaultOptions)
                ?? throw new JsonException("Failed to deserialize DID Document.");

            ValidateConsumption(doc, contentType);
            ValidateVerificationMethodControllers(doc);
            return doc;
        }
        catch (Exception ex) when (IsMalformedShape(ex))
        {
            throw MalformedDocument(ex);
        }
    }

    /// <summary>
    /// Consume (deserialize) a DID Document from UTF-8 bytes.
    /// </summary>
    /// <exception cref="JsonException">
    /// The input is malformed: for example ill-formed UTF-8, a duplicate member, an unpaired
    /// surrogate escape, or a missing or non-string verification-method controller.
    /// </exception>
    /// <exception cref="NetDid.Core.Exceptions.InvalidDidException">A DID-valued member is not a syntactically valid DID.</exception>
    public static DidDocument Deserialize(ReadOnlySpan<byte> utf8Json, string? contentType = null)
    {
        RejectMalformedJson(utf8Json);
        try
        {
            var doc = JsonSerializer.Deserialize<DidDocument>(utf8Json, DefaultOptions)
                ?? throw new JsonException("Failed to deserialize DID Document.");

            ValidateConsumption(doc, contentType);
            ValidateVerificationMethodControllers(doc);
            return doc;
        }
        catch (Exception ex) when (IsMalformedShape(ex))
        {
            throw MalformedDocument(ex);
        }
    }

    /// <summary>
    /// Consume a DID document that MAY contain verification methods without a <c>controller</c>.
    /// This is a method-internal path for did:peer:4's pre-contextualization template, whose
    /// verification-method controllers are legitimately omitted because they are derived from the
    /// DID — itself a hash of the document — at resolution time, then filled in during
    /// contextualization. Duplicate-member rejection and present-but-non-string-controller
    /// rejection still apply; only the "controller MUST be present" completeness rule
    /// (W3C DID Core §5.2, required of a <em>resolved</em> document) is deferred. Do not expose
    /// this on a public resolution/consumption path.
    /// </summary>
    internal static DidDocument DeserializeAllowingIncompleteVerificationMethods(string json)
    {
        RejectMalformedJson(json);
        try
        {
            var doc = JsonSerializer.Deserialize<DidDocument>(json, DefaultOptions)
                ?? throw new JsonException("Failed to deserialize DID Document.");

            ValidateConsumption(doc, contentType: null);
            return doc;
        }
        catch (Exception ex) when (IsMalformedShape(ex))
        {
            throw MalformedDocument(ex);
        }
    }

    // Class-closing net for the consumption boundary (issue #145): the converters guard the shapes
    // they know about, but any other JSON-access or model-construction failure on hostile input is
    // still malformed input, never a raw BCL exception. JsonException and InvalidDidException (a
    // NetDidException) pass through unchanged; a null json argument is rejected before the try.
    private static bool IsMalformedShape(Exception ex)
        => ex is KeyNotFoundException
            or InvalidOperationException
            or ArgumentException
            or FormatException
            or OverflowException;

    private static JsonException MalformedDocument(Exception inner)
        => new("The DID document is malformed.", inner);

    // Reject duplicate JSON members recursively at the consumption trust boundary. JsonDocument
    // with default options keeps the LAST of a duplicated member, so a decoy
    // ("controller":[attacker],"controller":self) would smuggle an unvalidated value past the
    // per-property guards and diverge from first-wins/reject consumers (issue #121). Fail closed.
    //
    // Unpaired surrogates map to this boundary's JsonException (issue #145). Comparing names means
    // decoding them, so an escaped one in a member NAME throws InvalidOperationException from
    // Parse, and a raw one anywhere in a string fails UTF-8 transcoding with ArgumentException.
    // String VALUES are decoded only when read, and extension values are kept as raw JsonElements
    // that nothing reads until Serialize, so every value is decoded once here as well.
    private static void RejectMalformedJson(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json, RejectDuplicatesOptions);
            Utf16Text.RequireDecodable(document.RootElement);
        }
        catch (Exception ex) when (ex is InvalidOperationException
            or (ArgumentException and not ArgumentNullException))
        {
            throw InvalidText(ex);
        }
    }

    private static void RejectMalformedJson(ReadOnlySpan<byte> utf8Json)
    {
        // The parser checks UTF-8 only in strings it decodes, and compares undecoded names by raw
        // bytes. An ill-formed name inside an extension object (a WTF-8 surrogate, or 0xFF beside
        // 0xFE) would pass this guard and decode to U+FFFD later. Require strict UTF-8, as the
        // string overload does by construction (issue #145).
        if (!Utf8.IsValid(utf8Json))
            throw new JsonException("The DID document is not valid UTF-8.");

        try
        {
            // JsonDocument.Parse has no ReadOnlySpan<byte> overload; copy to honor the same guard.
            using var document = JsonDocument.Parse(utf8Json.ToArray(), RejectDuplicatesOptions);
            Utf16Text.RequireDecodable(document.RootElement);
        }
        catch (InvalidOperationException ex)
        {
            throw InvalidText(ex);
        }
    }

    // Every caller string the converters write goes through Text (issue #145). Utf8JsonWriter
    // silently replaces an unpaired surrogate with U+FFFD, so the published bytes would differ from
    // the caller's model while Serialize reported success. Checking at the write site means the
    // check sees exactly what is written. DID values are syntax-checked ASCII and need no check.
    private static string Text(string value)
        => value is null
            // A required string (VM/service id or type, an alsoKnownAs entry) that is null would be
            // written as JSON null, which Deserialize rejects (issue #145).
            ? throw new ArgumentException("The DID document has a null string where one is required.", "doc")
            : Utf16Text.IsWellFormed(value)
                ? value
                : throw new ArgumentException(
                    "The DID document contains a string with an unpaired UTF-16 surrogate, which " +
                    "cannot be written as UTF-8 without altering it.",
                    "doc");

    // A caller dictionary with a non-ordinal comparer can hold two keys with the same text; writing
    // both would emit a duplicate member that Deserialize rejects (issues #121, #145).
    private static string UniqueName(HashSet<string> written, string key)
        => written.Add(Text(key))
            ? key
            : throw new ArgumentException("The DID document contains a duplicate member name.", "doc");

    // Caller JsonElement values are opaque to Text(): JsonElement.WriteTo would rewrite an
    // ill-formed UTF-8 string or member name inside one as U+FFFD (issue #145, PR #149 review).
    // Every name and string is decoded first, on the element actually being written.
    private static void WriteElement(Utf8JsonWriter writer, JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Undefined)
            throw new ArgumentException("The DID document contains an undefined JSON value.", "doc");

        try
        {
            Utf16Text.RequireDecodable(element);
        }
        catch (InvalidOperationException ex)
        {
            // Also covers ObjectDisposedException (an element whose document was disposed).
            throw new ArgumentException(
                "The DID document contains a JSON value that cannot be read, or whose text is not " +
                "well-formed UTF-8 or UTF-16, so it cannot be written without altering it.",
                "doc",
                ex);
        }

        element.WriteTo(writer);
    }

    // Shape guards for the consumption converters (issue #145). Without them a missing member threw
    // KeyNotFoundException, a wrong kind threw InvalidOperationException, and a null required string
    // or null array entry was accepted and crashed Serialize later. Messages name only the member.
    private static JsonElement RequireObject(JsonElement element, string what)
        => element.ValueKind == JsonValueKind.Object
            ? element
            : throw new JsonException($"{what} must be a JSON object; found {element.ValueKind}.");

    private static JsonElement.ArrayEnumerator RequireArray(JsonElement element, string member)
        => element.ValueKind == JsonValueKind.Array
            ? element.EnumerateArray()
            : throw new JsonException($"'{member}' must be a JSON array; found {element.ValueKind}.");

    private static string RequireString(JsonElement obj, string member, string owner)
        => obj.TryGetProperty(member, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!
            : throw new JsonException($"{owner}'s '{member}' must be a string.");

    // Fixed text: the offending content is attacker-controlled and is never echoed.
    private static JsonException InvalidText(Exception inner)
        => new("The DID document contains text that is not valid UTF-16 (an unpaired surrogate).", inner);

    // W3C DID Core §5.2: a verification method's `controller` is REQUIRED and cannot be inferred
    // from the document — it does NOT default to the DID subject. Reject a resolved document whose
    // verification method (top-level or embedded in a relationship) omits it. Without this an
    // attacker publishes a key with no controller and a consumer that (wrongly) treats absence as
    // self-control binds the attacker's key to the subject — the same forgery class as a dropped
    // non-string controller, reached with the simpler payload (issue #121).
    // Consumption boundary: a missing controller is malformed input → JsonException.
    private static void ValidateVerificationMethodControllers(DidDocument doc)
        => RequireVerificationMethodControllers(doc, id => new JsonException(
            $"Verification method '{id}' is missing the required 'controller' property " +
            "(W3C DID Core §5.2). A verification method's controller MUST be stated " +
            "explicitly; it does not default to the DID subject."));

    // Production boundary: authoring a resolved document without a controller is a caller error
    // → ArgumentException. NetDid must never publicly emit the omitted-controller shape it
    // rejects on consumption (issue #121 review): the check is symmetric on read and write.
    private static void RequireVerificationMethodControllersForProduction(DidDocument doc)
        => RequireVerificationMethodControllers(doc, id => new ArgumentException(
            $"Verification method '{id}' is missing the required 'controller' property " +
            "(W3C DID Core §5.2). A resolved DID document MUST state each verification method's " +
            "controller explicitly; it does not default to the DID subject.", nameof(doc)));

    private static void RequireVerificationMethodControllers(DidDocument doc, Func<string, Exception> onMissing)
    {
        if (doc.VerificationMethod is not null)
            foreach (var vm in doc.VerificationMethod)
                RequireController(vm);

        RequireControllerOnEmbedded(doc.Authentication);
        RequireControllerOnEmbedded(doc.AssertionMethod);
        RequireControllerOnEmbedded(doc.KeyAgreement);
        RequireControllerOnEmbedded(doc.CapabilityInvocation);
        RequireControllerOnEmbedded(doc.CapabilityDelegation);

        void RequireControllerOnEmbedded(IReadOnlyList<VerificationRelationshipEntry>? entries)
        {
            if (entries is null) return;
            foreach (var entry in entries)
                if (!entry.IsReference && entry.EmbeddedMethod is not null)
                    RequireController(entry.EmbeddedMethod);
        }

        void RequireController(VerificationMethod vm)
        {
            if (vm.Controller.Value is null)
                throw onMissing(vm.Id);
        }
    }

    private static void ValidateConsumption(DidDocument doc, string? contentType)
    {
        ValidateIdentifiers(doc, message => new JsonException(message));

        // JSON-LD consumption: MUST verify @context
        if (contentType == DidContentTypes.JsonLd)
        {
            if (doc.Context is null || doc.Context.Count == 0)
                throw new JsonException("JSON-LD DID Document must have @context.");

            var firstContext = doc.Context[0]?.ToString();
            if (firstContext != "https://www.w3.org/ns/did/v1")
                throw new JsonException("First @context entry must be 'https://www.w3.org/ns/did/v1'.");
        }
        // JSON consumption: MUST NOT require @context — no validation needed.
    }

    /// <summary>
    /// Compute the @context array for JSON-LD based on verification method types.
    /// </summary>
    internal static List<object> ComputeContext(DidDocument doc)
    {
        var contexts = new List<object> { "https://www.w3.org/ns/did/v1" };

        var vmTypes = new HashSet<string>();
        if (doc.VerificationMethod is not null)
            vmTypes = doc.VerificationMethod.Select(vm => vm.Type).Distinct().ToHashSet();

        // Also check embedded VMs in relationships
        AddEmbeddedVmTypes(doc.Authentication, vmTypes);
        AddEmbeddedVmTypes(doc.AssertionMethod, vmTypes);
        AddEmbeddedVmTypes(doc.KeyAgreement, vmTypes);
        AddEmbeddedVmTypes(doc.CapabilityInvocation, vmTypes);
        AddEmbeddedVmTypes(doc.CapabilityDelegation, vmTypes);

        foreach (var (type, context) in ExactVerificationMethodContexts)
        {
            if (vmTypes.Contains(type))
                contexts.Add(context);
        }
        // Add secp256k1-2019/v1 only when security/v2 is not already provided by the document
        // (did:ethr uses security/v2 per the reference JS resolver; did:key/did:peer use secp256k1-2019/v1)
        var docHasSecurityV2 = doc.Context?.Any(c => c is string s && s == "https://w3id.org/security/v2") == true;
        // A null type is rejected where the method is written (Text), not here.
        if (!docHasSecurityV2 && vmTypes.Any(t => t?.StartsWith("EcdsaSecp256k1", StringComparison.Ordinal) == true))
            contexts.Add("https://w3id.org/security/suites/secp256k1-2019/v1");

        // Append any additional context entries (strings or JSON objects) from the document
        if (doc.Context is not null)
        {
            foreach (var ctx in doc.Context)
            {
                if (ctx is null) continue;
                if (ctx is string ctxStr)
                {
                    if (!contexts.Any(c => c is string s && s == ctxStr))
                        contexts.Add(ctxStr);
                }
                else
                {
                    // Object-valued contexts (JsonElement) — always add
                    contexts.Add(ctx);
                }
            }
        }

        return contexts;
    }

    private static void AddEmbeddedVmTypes(
        IReadOnlyList<VerificationRelationshipEntry>? entries,
        HashSet<string> vmTypes)
    {
        if (entries is null) return;
        foreach (var entry in entries)
        {
            if (!entry.IsReference && entry.EmbeddedMethod is not null)
                vmTypes.Add(entry.EmbeddedMethod.Type);
        }
    }

    /// <summary>Internal wrapper to carry content type during serialization.</summary>
    internal record SerializationContext(DidDocument Document, string ContentType);

    // --- JSON Converters ---

    internal class DidDocumentJsonConverter : JsonConverter<SerializationContext>
    {
        public override SerializationContext Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => throw new NotSupportedException("Use DidDocumentDeserializerConverter instead.");

        public override void Write(Utf8JsonWriter writer, SerializationContext value, JsonSerializerOptions options)
        {
            var doc = value.Document;
            var isJsonLd = value.ContentType == DidContentTypes.JsonLd;

            writer.WriteStartObject();

            // @context (JSON-LD only)
            if (isJsonLd)
            {
                var contexts = ComputeContext(doc);
                writer.WritePropertyName("@context");
                WriteContextArray(writer, contexts);
            }

            // id (omitted for input documents where Id is not set)
            if (doc.Id.Value is not null)
                writer.WriteString("id", doc.Id.Value);

            // alsoKnownAs
            if (doc.AlsoKnownAs is { Count: > 0 })
            {
                writer.WritePropertyName("alsoKnownAs");
                writer.WriteStartArray();
                foreach (var alias in doc.AlsoKnownAs)
                    writer.WriteStringValue(Text(alias));
                writer.WriteEndArray();
            }

            // controller (string when 1, array when >1)
            if (doc.Controller is { Count: > 0 })
            {
                writer.WritePropertyName("controller");
                // Text rejects a default(Did), which would otherwise be written as JSON null.
                if (doc.Controller.Count == 1)
                    writer.WriteStringValue(Text(doc.Controller[0].Value!));
                else
                {
                    writer.WriteStartArray();
                    foreach (var c in doc.Controller)
                        writer.WriteStringValue(Text(c.Value!));
                    writer.WriteEndArray();
                }
            }

            // verificationMethod
            if (doc.VerificationMethod is { Count: > 0 })
            {
                writer.WritePropertyName("verificationMethod");
                writer.WriteStartArray();
                foreach (var vm in doc.VerificationMethod)
                    JsonSerializer.Serialize(writer, vm, options);
                writer.WriteEndArray();
            }

            // Verification relationships
            WriteRelationship(writer, "authentication", doc.Authentication, options);
            WriteRelationship(writer, "assertionMethod", doc.AssertionMethod, options);
            WriteRelationship(writer, "keyAgreement", doc.KeyAgreement, options);
            WriteRelationship(writer, "capabilityInvocation", doc.CapabilityInvocation, options);
            WriteRelationship(writer, "capabilityDelegation", doc.CapabilityDelegation, options);

            // service
            if (doc.Service is { Count: > 0 })
            {
                writer.WritePropertyName("service");
                writer.WriteStartArray();
                foreach (var svc in doc.Service)
                    JsonSerializer.Serialize(writer, svc, options);
                writer.WriteEndArray();
            }

            // Additional properties
            if (doc.AdditionalProperties is not null)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (key, val) in doc.AdditionalProperties)
                {
                    writer.WritePropertyName(UniqueName(names, key));
                    WriteElement(writer, val);
                }
            }

            writer.WriteEndObject();
        }

        private static void WriteContextArray(Utf8JsonWriter writer, List<object> contexts)
        {
            if (contexts.Count == 1 && contexts[0] is string singleStr)
            {
                writer.WriteStringValue(Text(singleStr));
                return;
            }

            writer.WriteStartArray();
            foreach (var ctx in contexts)
            {
                if (ctx is string str)
                    writer.WriteStringValue(Text(str));
                else if (ctx is JsonElement element)
                    WriteElement(writer, element);
                else
                    // ToString() would write an object as a string, and a JSON node's ToString()
                    // already replaces lone surrogates before any check could see them.
                    throw new ArgumentException(
                        "A DID document @context entry must be a string or a JsonElement; found " +
                        $"{ctx.GetType().Name}.",
                        "doc");
            }
            writer.WriteEndArray();
        }

        private static void WriteRelationship(Utf8JsonWriter writer, string name,
            IReadOnlyList<VerificationRelationshipEntry>? entries, JsonSerializerOptions options)
        {
            if (entries is not { Count: > 0 }) return;

            writer.WritePropertyName(name);
            writer.WriteStartArray();
            foreach (var entry in entries)
                JsonSerializer.Serialize(writer, entry, options);
            writer.WriteEndArray();
        }
    }

    internal class VerificationMethodJsonConverter : JsonConverter<VerificationMethod>
    {
        public override VerificationMethod Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            var root = RequireObject(jsonDoc.RootElement, "A verification method");

            string? publicKeyMultibase = null;
            JsonWebKey? publicKeyJwk = null;
            string? blockchainAccountId = null;

            if (root.TryGetProperty("publicKeyMultibase", out var pkm))
                publicKeyMultibase = pkm.GetString();
            if (root.TryGetProperty("publicKeyJwk", out var pkj))
                publicKeyJwk = JsonWebKeyConverter.FromJson(pkj.GetRawText());
            if (root.TryGetProperty("blockchainAccountId", out var bca))
                blockchainAccountId = bca.GetString();

            // Issue #121: a present-but-non-string controller must fail closed. Silently
            // dropping it made the document indistinguishable from one that OMITTED the
            // controller. Absence is enforced separately, after deserialization, at the
            // consumption boundary (ValidateVerificationMethodControllers) so did:peer:4's
            // pre-contextualization template — whose controller is legitimately omitted — can
            // opt out via the internal tolerant path. A present controller MUST be a single
            // string (W3C DID Core §5.2 Verification Methods).
            Did controller = default;
            if (root.TryGetProperty("controller", out var ctrlElement))
            {
                if (ctrlElement.ValueKind != JsonValueKind.String)
                    throw new JsonException(
                        "A verification method's 'controller' must be a single string " +
                        $"(W3C DID Core §5.2 Verification Methods); found {ctrlElement.ValueKind}.");
                controller = new Did(ctrlElement.GetString()!);
            }

            // Preserve unknown members (e.g. did:ethr's publicKeyHex, the ONLY key material
            // on those VMs) so a round-trip does not silently drop them. Mirrors ServiceJsonConverter.
            Dictionary<string, JsonElement>? additional = null;
            foreach (var prop in root.EnumerateObject())
            {
                if (prop.Name is "id" or "type" or "controller"
                    or "publicKeyMultibase" or "publicKeyJwk" or "blockchainAccountId")
                    continue;
                additional ??= new Dictionary<string, JsonElement>();
                additional[prop.Name] = prop.Value.Clone();
            }

            return new VerificationMethod
            {
                Id = RequireString(root, "id", "A verification method"),
                Type = RequireString(root, "type", "A verification method"),
                Controller = controller,
                PublicKeyMultibase = publicKeyMultibase,
                PublicKeyJwk = publicKeyJwk,
                BlockchainAccountId = blockchainAccountId,
                AdditionalProperties = additional
            };
        }

        public override void Write(Utf8JsonWriter writer, VerificationMethod value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("id", Text(value.Id));
            writer.WriteString("type", Text(value.Type));
            // Omit a transient default(Did) rather than emitting "controller": null (which the
            // consumer would then reject). A resolved document must carry a controller; that
            // completeness rule is enforced on the read side (ValidateVerificationMethodControllers).
            if (value.Controller.Value is not null)
                writer.WriteString("controller", value.Controller.Value);

            if (value.PublicKeyMultibase is not null)
                writer.WriteString("publicKeyMultibase", Text(value.PublicKeyMultibase));

            if (value.PublicKeyJwk is not null)
            {
                writer.WritePropertyName("publicKeyJwk");
                WriteJwk(writer, value.PublicKeyJwk);
            }

            if (value.BlockchainAccountId is not null)
                writer.WriteString("blockchainAccountId", Text(value.BlockchainAccountId));

            if (value.AdditionalProperties is not null)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (key, val) in value.AdditionalProperties)
                {
                    // Never let an additional member shadow a reserved one already written
                    // above — a colliding "publicKeyJwk" would duplicate the member and
                    // bypass the private-key sanitizer in WriteJwk.
                    if (key is "id" or "type" or "controller"
                        or "publicKeyMultibase" or "publicKeyJwk" or "blockchainAccountId")
                        continue;
                    writer.WritePropertyName(UniqueName(names, key));
                    WriteElement(writer, val);
                }
            }

            writer.WriteEndObject();
        }

        private static void WriteJwk(Utf8JsonWriter writer, JsonWebKey jwk)
        {
            // Write every PUBLIC member defined by RFC 7517 §4, RFC 7518 §6.2-6.3 and RFC 8037 §2,
            // and nothing else. Private key material (d, p, q, dp, dq, qi, oth, k) and unknown
            // members are never written. Before issue #145 only kty/crv/x/y were kept, so an RSA
            // key lost n and e. kty is REQUIRED (RFC 7517 §4.1): Text rejects a null one.
            if (string.IsNullOrEmpty(jwk.Kty))
                throw new ArgumentException("A publicKeyJwk must have a non-empty 'kty'.", "doc");
            writer.WriteStartObject();
            writer.WriteString("kty", Text(jwk.Kty));
            WriteOptional(writer, "crv", jwk.Crv);
            WriteOptional(writer, "x", jwk.X);
            WriteOptional(writer, "y", jwk.Y);
            WriteOptional(writer, "n", jwk.N);
            WriteOptional(writer, "e", jwk.E);
            WriteOptional(writer, "kid", jwk.Kid);
            WriteOptional(writer, "alg", jwk.Alg);
            WriteOptional(writer, "use", jwk.Use);
            WriteOptionalList(writer, "key_ops", jwk.KeyOps);
            WriteOptional(writer, "x5u", jwk.X5u);
            WriteOptionalList(writer, "x5c", jwk.X5c);
            WriteOptional(writer, "x5t", jwk.X5t);
            WriteOptional(writer, "x5t#S256", jwk.X5tS256);
            writer.WriteEndObject();
        }

        private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
        {
            if (value is not null)
                writer.WriteString(name, Text(value));
        }

        private static void WriteOptionalList(Utf8JsonWriter writer, string name, IList<string>? values)
        {
            if (values is not { Count: > 0 })
                return;
            writer.WritePropertyName(name);
            writer.WriteStartArray();
            foreach (var value in values)
                writer.WriteStringValue(Text(value));
            writer.WriteEndArray();
        }
    }

    internal class ServiceJsonConverter : JsonConverter<Service>
    {
        public override Service Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            var root = RequireObject(jsonDoc.RootElement, "A service");

            if (!root.TryGetProperty("serviceEndpoint", out var endpointElement))
                throw new JsonException(
                    "A service is missing the required 'serviceEndpoint' member (W3C DID Core §5.4).");
            var endpoint = DeserializeServiceEndpoint(endpointElement);

            Dictionary<string, JsonElement>? additional = null;
            foreach (var prop in root.EnumerateObject())
            {
                if (prop.Name is "id" or "type" or "serviceEndpoint") continue;
                additional ??= new Dictionary<string, JsonElement>();
                additional[prop.Name] = prop.Value.Clone();
            }

            return new Service
            {
                Id = RequireString(root, "id", "A service"),
                // DID Core also allows a set of strings here; the Service model holds one string,
                // so a set is rejected as before, now as JsonException.
                Type = RequireString(root, "type", "A service"),
                ServiceEndpoint = endpoint,
                AdditionalProperties = additional
            };
        }

        public override void Write(Utf8JsonWriter writer, Service value, JsonSerializerOptions options)
        {
            if (value.ServiceEndpoint is null)
                throw new ArgumentException("A service's serviceEndpoint is required.", "doc");
            writer.WriteStartObject();
            writer.WriteString("id", Text(value.Id));
            writer.WriteString("type", Text(value.Type));
            writer.WritePropertyName("serviceEndpoint");
            JsonSerializer.Serialize(writer, value.ServiceEndpoint, options);

            if (value.AdditionalProperties is not null)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (key, val) in value.AdditionalProperties)
                {
                    // A reserved name would emit a duplicate member that Deserialize rejects
                    // (the document-level #121 rule, applied to services; issue #145).
                    if (key is "id" or "type" or "serviceEndpoint")
                        throw new ArgumentException(
                            $"A service's AdditionalProperties contains the reserved member '{key}'.",
                            "doc");
                    writer.WritePropertyName(UniqueName(names, key));
                    WriteElement(writer, val);
                }
            }

            writer.WriteEndObject();
        }

        // W3C DID Core §5.4: a serviceEndpoint is a string, a map, or a set of one or more strings
        // and/or maps. A blank string, an empty set, or a set nested in a set is malformed; a nested
        // set also could not be serialized again at depth (issue #145).
        internal static ServiceEndpointValue DeserializeServiceEndpoint(JsonElement element)
            => DeserializeServiceEndpoint(element, allowSet: true);

        private static ServiceEndpointValue DeserializeServiceEndpoint(JsonElement element, bool allowSet)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.String:
                    var uri = element.GetString()!;
                    if (string.IsNullOrWhiteSpace(uri))
                        throw new JsonException("A serviceEndpoint string must not be blank.");
                    return ServiceEndpointValue.FromUri(uri);
                case JsonValueKind.Object:
                    return ServiceEndpointValue.FromMap(
                        element.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone()));
                case JsonValueKind.Array when allowSet:
                    var set = element.EnumerateArray()
                        .Select(e => DeserializeServiceEndpoint(e, allowSet: false))
                        .ToList();
                    if (set.Count == 0)
                        throw new JsonException("A serviceEndpoint set must contain at least one entry.");
                    return ServiceEndpointValue.FromSet(set);
                default:
                    throw new JsonException(
                        "A serviceEndpoint must be a string, a map, or a set of strings and maps " +
                        $"(W3C DID Core §5.4); found {element.ValueKind}.");
            }
        }
    }

    internal class ServiceEndpointValueJsonConverter : JsonConverter<ServiceEndpointValue>
    {
        public override ServiceEndpointValue Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            return ServiceJsonConverter.DeserializeServiceEndpoint(jsonDoc.RootElement);
        }

        public override void Write(Utf8JsonWriter writer, ServiceEndpointValue value, JsonSerializerOptions options)
        {
            if (value.IsUri)
            {
                writer.WriteStringValue(Text(value.Uri!));
            }
            else if (value.IsMap)
            {
                writer.WriteStartObject();
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var (key, val) in value.Map!)
                {
                    writer.WritePropertyName(UniqueName(names, key));
                    WriteElement(writer, val);
                }
                writer.WriteEndObject();
            }
            else if (value.IsSet)
            {
                writer.WriteStartArray();
                foreach (var item in value.Set!)
                {
                    // The model already forbids this; the writer enforces it too, so the shape the
                    // reader rejects can never be published (W3C DID Core §5.4, issue #145).
                    if (item is null || item.IsSet)
                        throw new ArgumentException(
                            "A serviceEndpoint set entry must be a URI or a map, not null or another set.",
                            "doc");
                    JsonSerializer.Serialize(writer, item, options);
                }
                writer.WriteEndArray();
            }
        }
    }

    internal class VerificationRelationshipEntryJsonConverter : JsonConverter<VerificationRelationshipEntry>
    {
        public override VerificationRelationshipEntry Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
                return VerificationRelationshipEntry.FromReference(reader.GetString()!);

            if (reader.TokenType == JsonTokenType.StartObject)
            {
                var vm = JsonSerializer.Deserialize<VerificationMethod>(ref reader, options)!;
                return VerificationRelationshipEntry.FromEmbedded(vm);
            }

            throw new JsonException($"Unexpected token type for verification relationship: {reader.TokenType}");
        }

        public override void Write(Utf8JsonWriter writer, VerificationRelationshipEntry value, JsonSerializerOptions options)
        {
            if (value.IsReference)
                writer.WriteStringValue(Text(value.Reference!));
            else
                JsonSerializer.Serialize(writer, value.EmbeddedMethod, options);
        }
    }

    /// <summary>Helper to convert JWK JSON string to JsonWebKey.</summary>
    private static class JsonWebKeyConverter
    {
        public static JsonWebKey FromJson(string json)
        {
            JsonWebKey jwk;
            try
            {
                jwk = new JsonWebKey(json);
            }
            catch (ArgumentException ex)
            {
                // IdentityModel reports a malformed key (e.g. "x": 5) as ArgumentException
                // (IDX10805); this consumption boundary reports malformed input as JsonException
                // (issue #145).
                throw new JsonException(
                    "The verification method's publicKeyJwk is not a valid JSON Web Key.", ex);
            }

            // kty is REQUIRED (RFC 7517 §4.1); without it no key type, and so no public member
            // set, is defined (issue #145).
            if (string.IsNullOrEmpty(jwk.Kty))
                throw new JsonException("The verification method's publicKeyJwk is missing 'kty'.");
            // The writer requires every key_ops/x5c entry to be a string, so reject a null entry
            // here rather than accept a key that cannot be written again.
            if (jwk.KeyOps.Contains(null!) || jwk.X5c.Contains(null!))
                throw new JsonException("The verification method's publicKeyJwk has a null key_ops or x5c entry.");
            return jwk;
        }
    }

    // --- Deserialization converter for DidDocument ---

    internal class DidDocumentDeserializerConverter : JsonConverter<DidDocument>
    {
        public override DidDocument Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            var root = jsonDoc.RootElement;

            List<object>? context = null;
            if (root.TryGetProperty("@context", out var ctxProp))
            {
                context = new List<object>();
                if (ctxProp.ValueKind == JsonValueKind.String)
                    context.Add(ctxProp.GetString()!);
                else if (ctxProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var elem in ctxProp.EnumerateArray())
                    {
                        if (elem.ValueKind == JsonValueKind.String)
                            context.Add(elem.GetString()!);
                        else
                            context.Add(elem.Clone());
                    }
                }
            }

            List<string>? alsoKnownAs = null;
            if (root.TryGetProperty("alsoKnownAs", out var akaProp))
                alsoKnownAs = RequireArray(akaProp, "alsoKnownAs")
                    .Select(e => e.ValueKind == JsonValueKind.String
                        ? e.GetString()!
                        : throw new JsonException(
                            "Every 'alsoKnownAs' entry must be a string (W3C DID Core §5.1.3)."))
                    .ToList();

            // Issue #121 (same class as the VM-level fix): any shape other than a string or
            // an array of strings previously collapsed to an EMPTY list — present-but-malformed
            // must be rejected, not silently read as "no controller" (W3C DID Core §5.1.2).
            List<Did>? controller = null;
            if (root.TryGetProperty("controller", out var ctrlProp))
            {
                controller = new List<Did>();
                if (ctrlProp.ValueKind == JsonValueKind.String)
                {
                    controller.Add(new Did(ctrlProp.GetString()!));
                }
                else if (ctrlProp.ValueKind == JsonValueKind.Array)
                {
                    foreach (var elem in ctrlProp.EnumerateArray())
                    {
                        if (elem.ValueKind != JsonValueKind.String)
                            throw new JsonException(
                                "A DID document's 'controller' must be a string or a set of " +
                                $"strings (W3C DID Core §5.1.2); found an array element of kind {elem.ValueKind}.");
                        controller.Add(new Did(elem.GetString()!));
                    }
                }
                else
                {
                    throw new JsonException(
                        "A DID document's 'controller' must be a string or a set of strings " +
                        $"(W3C DID Core §5.1.2); found {ctrlProp.ValueKind}.");
                }
            }

            List<VerificationMethod>? vms = null;
            if (root.TryGetProperty("verificationMethod", out var vmProp))
                vms = RequireArray(vmProp, "verificationMethod")
                    .Select(e => JsonSerializer.Deserialize<VerificationMethod>(
                        RequireObject(e, "A verification method").GetRawText(), options)!)
                    .ToList();

            var auth = ReadRelationship(root, "authentication", options);
            var assertion = ReadRelationship(root, "assertionMethod", options);
            var keyAgreement = ReadRelationship(root, "keyAgreement", options);
            var capInvoke = ReadRelationship(root, "capabilityInvocation", options);
            var capDelegate = ReadRelationship(root, "capabilityDelegation", options);

            List<Service>? services = null;
            if (root.TryGetProperty("service", out var svcProp))
                services = RequireArray(svcProp, "service")
                    .Select(e => JsonSerializer.Deserialize<Service>(
                        RequireObject(e, "A service").GetRawText(), options)!)
                    .ToList();

            // Collect additional properties
            var knownProperties = new HashSet<string>
            {
                "@context", "id", "alsoKnownAs", "controller", "verificationMethod",
                "authentication", "assertionMethod", "keyAgreement",
                "capabilityInvocation", "capabilityDelegation", "service"
            };

            Dictionary<string, JsonElement>? additional = null;
            foreach (var prop in root.EnumerateObject())
            {
                if (knownProperties.Contains(prop.Name)) continue;
                additional ??= new Dictionary<string, JsonElement>();
                additional[prop.Name] = prop.Value.Clone();
            }

            Did id = default;
            if (root.TryGetProperty("id", out var idProp) && idProp.ValueKind == JsonValueKind.String)
                id = new Did(idProp.GetString()!);

            return new DidDocument
            {
                Id = id,
                AlsoKnownAs = alsoKnownAs,
                Controller = controller,
                VerificationMethod = vms,
                Authentication = auth,
                AssertionMethod = assertion,
                KeyAgreement = keyAgreement,
                CapabilityInvocation = capInvoke,
                CapabilityDelegation = capDelegate,
                Service = services,
                Context = context,
                AdditionalProperties = additional
            };
        }

        public override void Write(Utf8JsonWriter writer, DidDocument value, JsonSerializerOptions options)
            => throw new NotSupportedException("Use SerializationContext converter for writing.");

        private static List<VerificationRelationshipEntry>? ReadRelationship(
            JsonElement root, string propertyName, JsonSerializerOptions options)
        {
            if (!root.TryGetProperty(propertyName, out var prop)) return null;

            return RequireArray(prop, propertyName).Select(e =>
            {
                if (e.ValueKind == JsonValueKind.String)
                {
                    var reference = e.GetString()!;
                    if (string.IsNullOrWhiteSpace(reference))
                        throw new JsonException($"A '{propertyName}' reference must not be blank.");
                    return VerificationRelationshipEntry.FromReference(reference);
                }

                var vm = JsonSerializer.Deserialize<VerificationMethod>(
                    RequireObject(e, $"A '{propertyName}' entry").GetRawText(), options)!;
                return VerificationRelationshipEntry.FromEmbedded(vm);
            }).ToList();
        }
    }
}
