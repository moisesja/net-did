Follow-up review on the current code: this issue is only partially fixed and should remain open.

What looks fixed:

- Verification method numbering is now 1-based.
- Explicit fragment service IDs are now preserved.
- Auto-generated service IDs now use `#service`, `#service-1`, ... rather than the earlier zero-based `#service-0` form.

What still keeps the issue open:

- Verification method IDs are still materialized as absolute DID URLs like `{did}#key-1` instead of the spec-defined relative IDs like `#key-1`.
- Service IDs are still materialized as absolute DID URLs like `{did}#service` / `{did}#my-custom-svc` instead of staying relative.
- New tests were added, but they currently assert the absolute-ID behavior. That means the test suite now locks in the remaining divergence instead of catching it.

The unresolved behavior is still visible in:

- `src/NetDid.Method.Peer/Numalgo2Handler.cs` where verification method IDs are built as `$\"{did}#key-{keyIndex}\"`
- `src/NetDid.Method.Peer/Numalgo2Handler.cs` where service IDs are generated and normalized into absolute DID URLs
- `tests/NetDid.Method.Peer.Tests/DidPeerMethodTests.cs` where the expectations explicitly assert absolute IDs

So this is materially improved, but it still does not fully resolve the original interoperability problem.
