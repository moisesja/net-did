# Documentation and CI overstate implemented methods and W3C conformance status

## Summary

The repository documentation currently makes stronger claims than the codebase and CI back up. The project docs are inconsistent with each other, and some of the conformance statements are not supported by the actual solution/workflow contents.

## Evidence

### Contributor guidance says five methods

- `AGENTS.md:7` says the library spans `did:key`, `did:peer`, `did:webvh`, `did:dht`, and `did:ethr`.

### PRD says four methods and full W3C validation

- `NetDidPRD.md:42-46` says NetDid provides four methods and that conformance is validated against the W3C DID Test Suite.
- `NetDidPRD.md:52-58` says every method must pass all W3C categories and that W3C conformance tests run in CI.
- `NetDidPRD.md:73-78` marks `did:webvh` and `did:ethr` as supported CRUD methods.

### Actual solution contents are much smaller

- `netdid.sln:8-24` includes only `NetDid.Core`, `NetDid.Method.Key`, `NetDid.Method.Peer`, their tests, and samples.
- There is no `NetDid.Method.WebVH`, `NetDid.Method.Ethr`, `NetDid.Method.Dht`, or `NetDid.TestSuite.W3C*` project in the repository.

### CI only builds and runs the current .NET tests

- `.github/workflows/ci.yml:21-28` runs restore/build/test only.
- There is no workflow here that clones or runs the external W3C DID Test Suite, and no internal W3C conformance test project in the solution.

### README is closer to reality

- `README.md:10` says only `did:key` and `did:peer` are implemented, with `did:webvh` and `did:ethr` planned.

## Why this matters

- Contributors and users get conflicting statements about what is implemented.
- “Specification-compliant” and “W3C test-suite validated” are high-trust claims; overstating them creates avoidable integration risk.
- The PRD is explicitly described as the source of truth, so drift there is especially costly.

## Expected behavior

- Documentation, PRD, contributor guidance, solution contents, and CI status should describe the same product state.

## Suggested fix

- Align `AGENTS.md`, `NetDidPRD.md`, and README with the current implementation status.
- Either add the missing method/conformance projects and workflows, or downgrade the claims until they exist.
- Consider tracking roadmap items separately from current-state claims to avoid mixing aspiration with shipped functionality.
