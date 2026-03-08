# Feature: Align `did:peer` with the current peer-DID spec purpose codes (`A`, `E`, `V`, `I`, `D`, `S`)

## Summary

The current `did:peer` design in `NetDidPRD.md` models numalgo 2 purpose prefixes as:

- `A` = key agreement
- `V` = verification / authentication
- `S` = service

However, the current peer-DID method spec defines the following purpose codes for `did:peer:2`:

- `A` = assertion
- `E` = key agreement (encryption)
- `V` = authentication (verification)
- `I` = capability invocation
- `D` = capability delegation
- `S` = service

This repo should support the current spec semantics and parsing/generation rules rather than a reduced or remapped subset.

## Motivation

- Interoperability with current peer-DID implementations depends on using the active purpose code table from the spec.
- The current PRD mapping risks producing or accepting `did:peer:2` values that do not round-trip correctly with external agents.
- `A` currently has a conflicting meaning in the PRD versus the current spec.

## Requested Change

Implement full support for the current peer-DID spec in the `did:peer` method package and align the PRD accordingly.

At minimum:

1. Update the PRD and public API model for `did:peer:2` purpose codes to match the current spec.
2. Support parsing and generation for keys with purpose codes:
   - `A` assertion
   - `E` key agreement
   - `V` authentication
   - `I` capability invocation
   - `D` capability delegation
   - `S` service
3. Map each code to the correct DID Document verification relationship(s).
4. Preserve service encoding/decoding behavior for `S` entries per spec abbreviations.
5. Add round-trip tests using current-spec `did:peer:2` examples, including mixed-purpose keys and service blocks.

## Acceptance Criteria

- `did:peer:2` generation emits purpose codes matching the current peer-DID specification.
- `did:peer:2` resolution correctly expands each supported code into the expected DID Document relationship arrays.
- The implementation accepts real-world current-spec peer DIDs using `E` and `V`.
- The PRD no longer documents `A` as key agreement.
- Tests cover parsing, generation, and DID Document materialization for all supported purpose codes.

## References

- Peer DID Method Specification: https://identity.foundation/peer-did-method-spec/index.html
- Current repo PRD `did:peer` section: `NetDidPRD.md`
