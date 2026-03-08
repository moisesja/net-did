# did:peer numalgo 4 resolution does not faithfully preserve or rewrite the input document

## Summary

`Numalgo4Handler.BuildResolvedDocument` only rewrites part of the input document. It leaves some placeholder values untouched and drops other document fields entirely.

## Affected code

- `src/NetDid.Method.Peer/Numalgo4Handler.cs:106-139`
- `src/NetDid.Method.Peer/Numalgo4Handler.cs:150-168`

## Why this matters

Numalgo 4 resolution should reconstruct a resolved DID document from the encoded long-form input. Today the reconstructed document can contain the placeholder controller DID, keep embedded relationship IDs/controllers un-rewritten, and lose top-level `@context` / `AdditionalProperties`.

## Reproduction

Create a numalgo 4 input document with:

- `Id = did:peer:placeholder`
- `Controller = [ "did:peer:placeholder" ]`
- an embedded verification method inside `authentication`
- a custom `Context`
- top-level `AdditionalProperties`

Then:

1. Call `DidPeerMethod.CreateAsync(...)` with `PeerNumalgo.Four`.
2. Resolve the resulting long-form DID with `ResolveAsync(...)`.
3. Inspect the resolved document.

Observed from the current implementation:

- `Controller` is copied directly from the placeholder input document.
- Embedded relationship entries are returned unchanged because `PrefixRelationships` only rewrites references.
- `Context` is not copied into the resolved document.
- top-level `AdditionalProperties` are not copied into the resolved document.

## Expected behavior

- All DID references that point at the placeholder input DID should be rewritten to the actual resolved DID.
- Embedded verification methods should be rewritten just like top-level verification methods.
- `Context` and top-level additional properties should round-trip.

## Actual behavior

- Only top-level verification methods and string references get partial rewriting.
- Several valid document properties are dropped.

## Suggested fix

- Rewrite `Controller` values when they match the input DID.
- Rewrite embedded verification methods inside relationship arrays.
- Preserve `Context` and `AdditionalProperties`.
- Add round-trip tests that assert full input-document fidelity for numalgo 4.
