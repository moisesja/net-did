# JSON-LD serializer/deserializer drops or rejects object-valued `@context` entries

## Summary

The DID document serializer only handles string contexts. Object-valued `@context` entries are either dropped/stringified on serialization or rejected during deserialization.

## Affected code

- `src/NetDid.Core/Serialization/DidDocumentSerializer.cs:118-126`
- `src/NetDid.Core/Serialization/DidDocumentSerializer.cs:234-245`
- `src/NetDid.Core/Serialization/DidDocumentSerializer.cs:463-471`

## Why this matters

DID documents commonly use JSON-LD term definitions in `@context`. The current implementation advertises JSON-LD support, but it cannot round-trip valid context objects. That breaks standards compliance and can silently strip semantic definitions from a document.

## Reproduction

### Deserialization failure

```csharp
var json = """
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    { "example": "https://example.com/ns#" }
  ],
  "id": "did:example:123"
}
""";

DidDocumentSerializer.Deserialize(json, DidContentTypes.JsonLd);
// throws JsonException
```

### Serialization loss

```csharp
var doc = new DidDocument
{
    Id = new Did("did:example:123"),
    Context =
    [
        "https://www.w3.org/ns/did/v1",
        JsonDocument.Parse("""{"example":"https://example.com/ns#"}""").RootElement.Clone()
    ]
};

var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.JsonLd);
// extension context is dropped / not emitted as a JSON object
```

## Expected behavior

- Object-valued context entries should round-trip as JSON objects.
- JSON-LD serialization should preserve the document's explicit context extensions.

## Actual behavior

- `WriteContextArray` serializes every entry with `WriteStringValue(ctx.ToString())`.
- The deserializer calls `GetString()` for array elements, which fails for object entries.

## Suggested fix

- Model `Context` with a type that can distinguish strings from object contexts.
- Serialize `JsonElement`/dictionary contexts as JSON objects, not strings.
- Add round-trip tests for object-valued `@context` entries.
