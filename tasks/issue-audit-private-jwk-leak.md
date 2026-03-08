# Serializer leaks private JWK `d` values in `publicKeyJwk`

## Summary

`DidDocumentSerializer` writes the private JWK member `d` whenever a `VerificationMethod.PublicKeyJwk` contains it. That turns a DID document serialization path into a secret-exfiltration path.

## Affected code

- `src/NetDid.Core/Serialization/DidDocumentSerializer.cs:300-320`

## Why this matters

`publicKeyJwk` is supposed to publish public verification material. If a caller accidentally passes a full JWK, the serializer emits the private component into the DID document. That can leak signing keys into logs, HTTP responses, fixtures, or persisted documents.

## Reproduction

1. Construct a `DidDocument` with a `JsonWebKey2020` verification method.
2. Set `VerificationMethod.PublicKeyJwk` to a `JsonWebKey` that includes `D`.
3. Call `DidDocumentSerializer.Serialize(doc, DidContentTypes.Json)`.
4. Observe that the resulting JSON contains `"d":"..."`.

Minimal example:

```csharp
var doc = new DidDocument
{
    Id = new Did("did:example:123"),
    VerificationMethod =
    [
        new VerificationMethod
        {
            Id = "did:example:123#key-1",
            Type = "JsonWebKey2020",
            Controller = new Did("did:example:123"),
            PublicKeyJwk = new JsonWebKey
            {
                Kty = "OKP",
                Crv = "Ed25519",
                X = "public-x",
                D = "private-d"
            }
        }
    ]
};

var json = DidDocumentSerializer.Serialize(doc, DidContentTypes.Json);
// json contains: "d":"private-d"
```

## Expected behavior

- The serializer should never emit private key members from `publicKeyJwk`.
- Ideally it should either strip private members (`d`, RSA private fields, etc.) or reject non-public JWKs up front.

## Actual behavior

- `WriteJwk` serializes `jwk.D` directly.

## Suggested fix

- Sanitize `PublicKeyJwk` before serialization so only public members are written.
- Add regression tests that fail if any private JWK member is emitted from a DID document.
