Follow-up review on the current code: this issue is only partially fixed and should remain open.

What looks fixed:

- Generated `P-256`, `P-384`, and `secp256k1` public keys are now compressed in `DefaultKeyGenerator`.
- `did:key` and `did:peer:0` resolution now reject payloads with invalid key lengths.
- JWK conversion was updated so compressed EC keys can be converted correctly.

What still keeps the issue open:

- The create path still trusts caller-supplied `ExistingKey.PublicKey` bytes as-is. That means an external signer that exposes an uncompressed `P-256`, `P-384`, or `secp256k1` key can still produce a non-spec DID, because the code does not normalize the caller-provided key into the compressed representation before building the identifier.
- Resolution currently validates length only. For EC keys, that is not enough to prove the payload is a valid point. A malformed compressed point with the right byte length can still get through the current `IsValidKeyLength(...)` check and be materialized into a DID Document.
- The targeted tests cover generated keys, but they do not cover the remaining failure modes above:
  - create from an external `ExistingKey` with uncompressed EC key bytes
  - resolve a malformed compressed EC point that has the correct length but is not a valid point

The unresolved parts are visible in:

- `src/NetDid.Method.Key/DidKeyMethod.cs` where `ExistingKey.PublicKey` is used directly during creation
- `src/NetDid.Method.Peer/Numalgo0Handler.cs` where `ExistingKey.PublicKey` is also used directly
- `src/NetDid.Method.Key/DidKeyMethod.cs` and `src/NetDid.Method.Peer/Numalgo0Handler.cs` where resolution relies on `IsValidKeyLength(...)` rather than full EC point validation

So the generated-key path improved, but the broader issue is not fully closed.
