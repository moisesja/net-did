Follow-up review on the current code: this issue has moved forward, but it is not fully resolved yet, so it should stay open.

What looks fixed:

- The long-form suffix is now multibase/base58btc rather than raw base64url JSON.
- The implementation now prefixes the document bytes with the JSON multicodec before encoding.
- `alsoKnownAs` now includes the short-form DID.

What still keeps the issue open:

- The create path still serializes the caller-supplied `DidDocument` directly and then rewrites it after the DID has already been derived. In other words, the encoded artifact is still built from the pre-rewrite input document, not from a dedicated contextualized/pre-resolution representation.
- The API still requires `DidDocument.Id`, which means callers still need the placeholder-ID workflow that this issue called out. That placeholder-based design is still visible in the tests and still appears to be part of the expected usage model.
- Because of that API shape, the implementation still does not cleanly represent the spec concept of “input document before contextualization”; it represents “already-built DID document that we patch after encoding”.

Concretely, the unresolved parts are still visible in:

- `src/NetDid.Method.Peer/Numalgo4Handler.cs` where `Create(...)` serializes `options.InputDocument` directly and only afterwards calls `BuildResolvedDocument(...)`
- `src/NetDid.Core/Model/DidDocument.cs` where `Id` is still required
- `tests/NetDid.Method.Peer.Tests/DidPeerMethodTests.cs` where numalgo 4 inputs still use `did:peer:placeholder`

So this is better than before, but I would still classify it as a partial fix rather than a full resolution.
