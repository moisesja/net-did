using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;
using NetDid.Core.Model;

namespace NetDid.Core.Serialization;

/// <summary>
/// Serializes and deserializes DID Documents per W3C DID Core §6 production/consumption rules.
/// </summary>
public static class DidDocumentSerializer
{
    private static readonly JsonSerializerOptions DefaultOptions = CreateOptions();

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
    public static string Serialize(DidDocument doc, string contentType = DidContentTypes.JsonLd,
        JsonSerializerOptions? options = null)
    {
        var effective = options ?? DefaultOptions;
        var wrapper = new SerializationContext(doc, contentType);
        return JsonSerializer.Serialize(wrapper, effective);
    }

    /// <summary>
    /// Produce the DID Document as UTF-8 bytes.
    /// </summary>
    public static byte[] SerializeToUtf8(DidDocument doc, string contentType = DidContentTypes.JsonLd,
        JsonSerializerOptions? options = null)
    {
        var effective = options ?? DefaultOptions;
        var wrapper = new SerializationContext(doc, contentType);
        return JsonSerializer.SerializeToUtf8Bytes(wrapper, effective);
    }

    /// <summary>
    /// Consume (deserialize) a DID Document from JSON.
    /// </summary>
    public static DidDocument Deserialize(string json, string? contentType = null)
    {
        var doc = JsonSerializer.Deserialize<DidDocument>(json, DefaultOptions)
            ?? throw new JsonException("Failed to deserialize DID Document.");

        ValidateConsumption(doc, contentType);
        return doc;
    }

    /// <summary>
    /// Consume (deserialize) a DID Document from UTF-8 bytes.
    /// </summary>
    public static DidDocument Deserialize(ReadOnlySpan<byte> utf8Json, string? contentType = null)
    {
        var doc = JsonSerializer.Deserialize<DidDocument>(utf8Json, DefaultOptions)
            ?? throw new JsonException("Failed to deserialize DID Document.");

        ValidateConsumption(doc, contentType);
        return doc;
    }

    private static void ValidateConsumption(DidDocument doc, string? contentType)
    {
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

        if (doc.VerificationMethod is null) return contexts;

        var vmTypes = doc.VerificationMethod.Select(vm => vm.Type).Distinct().ToHashSet();

        // Also check embedded VMs in relationships
        AddEmbeddedVmTypes(doc.Authentication, vmTypes);
        AddEmbeddedVmTypes(doc.AssertionMethod, vmTypes);
        AddEmbeddedVmTypes(doc.KeyAgreement, vmTypes);
        AddEmbeddedVmTypes(doc.CapabilityInvocation, vmTypes);
        AddEmbeddedVmTypes(doc.CapabilityDelegation, vmTypes);

        if (vmTypes.Contains("Multikey"))
            contexts.Add("https://w3id.org/security/multikey/v1");
        if (vmTypes.Contains("JsonWebKey2020"))
            contexts.Add("https://w3id.org/security/suites/jws-2020/v1");
        if (vmTypes.Any(t => t.StartsWith("EcdsaSecp256k1")))
            contexts.Add("https://w3id.org/security/suites/secp256k1-2019/v1");

        // Append any additional context URIs from the document
        if (doc.Context is not null)
        {
            foreach (var ctx in doc.Context)
            {
                var ctxStr = ctx?.ToString();
                if (ctxStr is not null && !contexts.Any(c => c.ToString() == ctxStr))
                    contexts.Add(ctx!);
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

            // id
            writer.WriteString("id", doc.Id.Value);

            // alsoKnownAs
            if (doc.AlsoKnownAs is { Count: > 0 })
            {
                writer.WritePropertyName("alsoKnownAs");
                JsonSerializer.Serialize(writer, doc.AlsoKnownAs, options);
            }

            // controller (string when 1, array when >1)
            if (doc.Controller is { Count: > 0 })
            {
                writer.WritePropertyName("controller");
                if (doc.Controller.Count == 1)
                    writer.WriteStringValue(doc.Controller[0].Value);
                else
                {
                    writer.WriteStartArray();
                    foreach (var c in doc.Controller)
                        writer.WriteStringValue(c.Value);
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
                foreach (var (key, val) in doc.AdditionalProperties)
                {
                    writer.WritePropertyName(key);
                    val.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        private static void WriteContextArray(Utf8JsonWriter writer, List<object> contexts)
        {
            if (contexts.Count == 1)
            {
                writer.WriteStringValue(contexts[0].ToString());
                return;
            }

            writer.WriteStartArray();
            foreach (var ctx in contexts)
                writer.WriteStringValue(ctx.ToString());
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
            var root = jsonDoc.RootElement;

            string? publicKeyMultibase = null;
            JsonWebKey? publicKeyJwk = null;
            string? blockchainAccountId = null;

            if (root.TryGetProperty("publicKeyMultibase", out var pkm))
                publicKeyMultibase = pkm.GetString();
            if (root.TryGetProperty("publicKeyJwk", out var pkj))
                publicKeyJwk = JsonWebKeyConverter.FromJson(pkj.GetRawText());
            if (root.TryGetProperty("blockchainAccountId", out var bca))
                blockchainAccountId = bca.GetString();

            return new VerificationMethod
            {
                Id = root.GetProperty("id").GetString()!,
                Type = root.GetProperty("type").GetString()!,
                Controller = new Did(root.GetProperty("controller").GetString()!),
                PublicKeyMultibase = publicKeyMultibase,
                PublicKeyJwk = publicKeyJwk,
                BlockchainAccountId = blockchainAccountId
            };
        }

        public override void Write(Utf8JsonWriter writer, VerificationMethod value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("id", value.Id);
            writer.WriteString("type", value.Type);
            writer.WriteString("controller", value.Controller.Value);

            if (value.PublicKeyMultibase is not null)
                writer.WriteString("publicKeyMultibase", value.PublicKeyMultibase);

            if (value.PublicKeyJwk is not null)
            {
                writer.WritePropertyName("publicKeyJwk");
                WriteJwk(writer, value.PublicKeyJwk);
            }

            if (value.BlockchainAccountId is not null)
                writer.WriteString("blockchainAccountId", value.BlockchainAccountId);

            writer.WriteEndObject();
        }

        private static void WriteJwk(Utf8JsonWriter writer, JsonWebKey jwk)
        {
            // Only write public JWK members — never emit private key material (d, p, q, dp, dq, qi, k, oth).
            writer.WriteStartObject();
            if (jwk.Kty is not null) writer.WriteString("kty", jwk.Kty);
            if (jwk.Crv is not null) writer.WriteString("crv", jwk.Crv);
            if (jwk.X is not null) writer.WriteString("x", jwk.X);
            if (jwk.Y is not null) writer.WriteString("y", jwk.Y);
            writer.WriteEndObject();
        }
    }

    internal class ServiceJsonConverter : JsonConverter<Service>
    {
        public override Service Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            using var jsonDoc = JsonDocument.ParseValue(ref reader);
            var root = jsonDoc.RootElement;

            var endpointConverter = new ServiceEndpointValueJsonConverter();
            var endpointElement = root.GetProperty("serviceEndpoint");
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
                Id = root.GetProperty("id").GetString()!,
                Type = root.GetProperty("type").GetString()!,
                ServiceEndpoint = endpoint,
                AdditionalProperties = additional
            };
        }

        public override void Write(Utf8JsonWriter writer, Service value, JsonSerializerOptions options)
        {
            writer.WriteStartObject();
            writer.WriteString("id", value.Id);
            writer.WriteString("type", value.Type);
            writer.WritePropertyName("serviceEndpoint");
            JsonSerializer.Serialize(writer, value.ServiceEndpoint, options);

            if (value.AdditionalProperties is not null)
            {
                foreach (var (key, val) in value.AdditionalProperties)
                {
                    writer.WritePropertyName(key);
                    val.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        internal static ServiceEndpointValue DeserializeServiceEndpoint(JsonElement element)
        {
            return element.ValueKind switch
            {
                JsonValueKind.String => ServiceEndpointValue.FromUri(element.GetString()!),
                JsonValueKind.Object => ServiceEndpointValue.FromMap(
                    element.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone())),
                JsonValueKind.Array => ServiceEndpointValue.FromSet(
                    element.EnumerateArray().Select(DeserializeServiceEndpoint).ToList()),
                _ => throw new JsonException($"Unexpected serviceEndpoint value kind: {element.ValueKind}")
            };
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
                writer.WriteStringValue(value.Uri);
            }
            else if (value.IsMap)
            {
                writer.WriteStartObject();
                foreach (var (key, val) in value.Map!)
                {
                    writer.WritePropertyName(key);
                    val.WriteTo(writer);
                }
                writer.WriteEndObject();
            }
            else if (value.IsSet)
            {
                writer.WriteStartArray();
                foreach (var item in value.Set!)
                    JsonSerializer.Serialize(writer, item, options);
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
                writer.WriteStringValue(value.Reference);
            else
                JsonSerializer.Serialize(writer, value.EmbeddedMethod, options);
        }
    }

    /// <summary>Helper to convert JWK JSON string to JsonWebKey.</summary>
    private static class JsonWebKeyConverter
    {
        public static JsonWebKey FromJson(string json)
        {
            return new JsonWebKey(json);
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
                    context.AddRange(ctxProp.EnumerateArray().Select(e => (object)e.GetString()!));
            }

            List<string>? alsoKnownAs = null;
            if (root.TryGetProperty("alsoKnownAs", out var akaProp))
                alsoKnownAs = akaProp.EnumerateArray().Select(e => e.GetString()!).ToList();

            List<Did>? controller = null;
            if (root.TryGetProperty("controller", out var ctrlProp))
            {
                controller = new List<Did>();
                if (ctrlProp.ValueKind == JsonValueKind.String)
                    controller.Add(new Did(ctrlProp.GetString()!));
                else if (ctrlProp.ValueKind == JsonValueKind.Array)
                    controller.AddRange(ctrlProp.EnumerateArray().Select(e => new Did(e.GetString()!)));
            }

            List<VerificationMethod>? vms = null;
            if (root.TryGetProperty("verificationMethod", out var vmProp))
                vms = vmProp.EnumerateArray()
                    .Select(e => JsonSerializer.Deserialize<VerificationMethod>(e.GetRawText(), options)!)
                    .ToList();

            var auth = ReadRelationship(root, "authentication", options);
            var assertion = ReadRelationship(root, "assertionMethod", options);
            var keyAgreement = ReadRelationship(root, "keyAgreement", options);
            var capInvoke = ReadRelationship(root, "capabilityInvocation", options);
            var capDelegate = ReadRelationship(root, "capabilityDelegation", options);

            List<Service>? services = null;
            if (root.TryGetProperty("service", out var svcProp))
                services = svcProp.EnumerateArray()
                    .Select(e => JsonSerializer.Deserialize<Service>(e.GetRawText(), options)!)
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

            return new DidDocument
            {
                Id = new Did(root.GetProperty("id").GetString()!),
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

            return prop.EnumerateArray().Select(e =>
            {
                if (e.ValueKind == JsonValueKind.String)
                    return VerificationRelationshipEntry.FromReference(e.GetString()!);

                var vm = JsonSerializer.Deserialize<VerificationMethod>(e.GetRawText(), options)!;
                return VerificationRelationshipEntry.FromEmbedded(vm);
            }).ToList();
        }
    }
}
