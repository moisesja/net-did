# DID parser accepts DID URLs and illegal characters as valid bare DIDs

## Summary

`DidParser.IsValid` uses `^did:[a-z0-9]+:.+$`, which is far looser than the DID Core grammar. The parser currently accepts DID URLs and illegal method-specific-id characters as if they were valid bare DIDs.

## Affected code

- `src/NetDid.Core/Parsing/DidParser.cs:11-29`
- `src/NetDid.Core/Model/Did.cs:15-23`

## Why this matters

The `Did` value object promises that any constructed value is syntactically valid. That guarantee is false today. Invalid identifiers can enter the type system, and callers cannot reliably distinguish a DID from a DID URL.

## Reproduction

All of the following currently succeed or return `true`:

```csharp
DidParser.IsValid("did:example:abc#frag");      // true, but this is a DID URL
DidParser.IsValid("did:example:abc def");       // true, space should be rejected
new Did("did:example:abc#frag");                // accepted by the Did value object
```

This URL is also misparsed:

```csharp
var parsed = DidParser.ParseDidUrl("did:example:abc;service=files");

parsed!.Did.Value   // "did:example:abc;service=files"
parsed.Query        // null
```

Instead of modeling DID parameters, the parser treats them as part of the bare DID.

## Expected behavior

- Bare DID validation should reject fragments, queries, paths, spaces, and other illegal characters.
- DID URL parsing should distinguish the base DID from DID parameters/path/query/fragment per DID Core.

## Actual behavior

- Anything after the second colon is accepted by `DidRegex`.
- `Did` construction inherits that loose validation.
- `ParseDidUrl` has no model for DID parameters and folds them into the base DID.

## Suggested fix

- Replace the permissive regex with validation aligned to the DID Core ABNF.
- Add explicit parsing for DID parameters in `DidUrl`.
- Add regression tests for fragments, paths, spaces, percent-encoding, and DID parameters.
