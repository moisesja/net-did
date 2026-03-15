# W3C DID Core Conformance Report

Generated: 2026-03-15T16:25:01Z

## Summary

| Method | Total | Passed | Failed |
|--------|-------|--------|--------|
| did:key | 57 | 57 | 0 |
| did:peer | 66 | 66 | 0 |
| did:webvh | 57 | 57 | 0 |

## did-identifier (section 3.1)

| Statement | Description | did:key | did:peer | did:webvh |
|-----------|-------------|----------|----------|----------|
| 3.1-1 | DID conforms to ABNF syntax | PASS | PASS | PASS |
| 3.1-10 | FullUrl reconstructs correctly | PASS | PASS | PASS |
| 3.1-2 | Method name is lowercase alphanumeric | PASS | PASS | PASS |
| 3.1-3 | Method-specific-id contains only valid characters | PASS | PASS | PASS |
| 3.1-4 | Invalid DID syntax is rejected | PASS | PASS | N/A |
| 3.1-5 | DID URL with fragment parses correctly | PASS | PASS | PASS |
| 3.1-6 | DID URL with query parses correctly | PASS | PASS | PASS |
| 3.1-7 | DID URL with path parses correctly | PASS | PASS | PASS |
| 3.1-8 | DID URL with parameters parses correctly | PASS | PASS | PASS |
| 3.1-9 | Invalid DID URL is rejected | PASS | PASS | N/A |

## did-core-properties (section 4)

| Statement | Description | did:key | did:peer | did:webvh |
|-----------|-------------|----------|----------|----------|
| 4-1 | Document id is present and non-empty | PASS | PASS | PASS |
| 4-10 | VM has exactly one key representation | PASS | PASS | PASS |
| 4-11 | Multibase key is non-empty and starts with 'z' | PASS | PASS | PASS |
| 4-12 | JWK does not contain private key material | PASS | N/A | N/A |
| 4-13 | Verification method IDs are unique | PASS | PASS | PASS |
| 4-14 | authentication entries are valid references or embedded VMs | PASS | PASS | PASS |
| 4-15 | assertionMethod entries are valid references or embedded VMs | PASS | PASS | PASS |
| 4-16 | keyAgreement entries are valid references or embedded VMs | PASS | PASS | PASS |
| 4-17 | capabilityInvocation entries are valid references or embedded VMs | PASS | PASS | PASS |
| 4-18 | capabilityDelegation entries are valid references or embedded VMs | PASS | PASS | PASS |
| 4-19 | Relationship references resolve to existing VMs | PASS | PASS | PASS |
| 4-2 | Document id conforms to DID syntax | PASS | PASS | PASS |
| 4-20 | Service has required properties (id, type, serviceEndpoint) | N/A | PASS | PASS |
| 4-21 | ServiceEndpoint is exactly one of URI, map, or set | N/A | PASS | PASS |
| 4-22 | Service IDs are unique within document | N/A | PASS | PASS |
| 4-23 | Service endpoint URI is valid | N/A | PASS | PASS |
| 4-3 | Document id matches resolved DID | PASS | PASS | PASS |
| 4-4 | Controller values conform to DID syntax | N/A | PASS | N/A |
| 4-5 | Controller serializes as string or array | N/A | PASS | N/A |
| 4-6 | VM has required properties (id, type, controller) | PASS | PASS | PASS |
| 4-7 | VM id conforms to DID URL syntax | PASS | PASS | PASS |
| 4-8 | VM type is non-empty string | PASS | PASS | PASS |
| 4-9 | VM controller conforms to DID syntax | PASS | PASS | PASS |

## did-production (section 6)

| Statement | Description | did:key | did:peer | did:webvh |
|-----------|-------------|----------|----------|----------|
| 6-1 | JSON production produces valid JSON | PASS | PASS | PASS |
| 6-10 | JSON-LD round-trips via deserialization | PASS | PASS | PASS |
| 6-11 | Missing @context rejected on JSON-LD consumption | PASS | PASS | N/A |
| 6-12 | Wrong first @context rejected on JSON-LD consumption | PASS | PASS | N/A |
| 6-2 | JSON production omits @context | PASS | PASS | PASS |
| 6-3 | id serialized as string | PASS | PASS | PASS |
| 6-4 | verificationMethod serialized as array | PASS | PASS | PASS |
| 6-5 | Null properties omitted from JSON | PASS | PASS | PASS |
| 6-6 | Relationship references serialized as strings | PASS | PASS | PASS |
| 6-7 | JSON-LD production includes @context | PASS | PASS | PASS |
| 6-8 | First @context is https://www.w3.org/ns/did/v1 | PASS | PASS | PASS |
| 6-9 | Context includes method-specific entries (Multikey) | PASS | PASS | PASS |

## did-resolution (section 7.1)

| Statement | Description | did:key | did:peer | did:webvh |
|-----------|-------------|----------|----------|----------|
| 7.1-1 | Valid DID resolution returns non-null document | PASS | PASS | PASS |
| 7.1-10 | Error property is non-empty string on failure | PASS | PASS | PASS |
| 7.1-2 | Valid DID resolution has no error | PASS | PASS | PASS |
| 7.1-3 | Resolution metadata contentType is set | PASS | PASS | PASS |
| 7.1-4 | Resolved document id matches requested DID | PASS | PASS | PASS |
| 7.1-5 | Invalid DID returns invalidDid error | PASS | PASS | PASS |
| 7.1-6 | Unknown method returns methodNotSupported error | PASS | PASS | N/A |
| 7.1-7 | Nonexistent DID returns error with null document | PASS | PASS | PASS |
| 7.1-8 | ContentType is a valid media type | PASS | PASS | PASS |
| 7.1-9 | Error is null on successful resolution | PASS | PASS | PASS |

## did-url-dereferencing (section 7.2)

| Statement | Description | did:key | did:peer | did:webvh |
|-----------|-------------|----------|----------|----------|
| 7.2-1 | Fragment dereferencing returns VerificationMethod | PASS | PASS | PASS |
| 7.2-10 | ContentType is set on successful dereference | PASS | PASS | PASS |
| 7.2-11 | Error is null on successful dereference | PASS | PASS | PASS |
| 7.2-12 | Error is set on failed dereference | PASS | PASS | N/A |
| 7.2-2 | Returned VM id contains the requested fragment | PASS | PASS | PASS |
| 7.2-3 | Service query returns redirect URL | N/A | PASS | PASS |
| 7.2-4 | Service query with relativeRef constructs correct URL | N/A | PASS | PASS |
| 7.2-5 | Bare DID dereference returns full document | PASS | PASS | PASS |
| 7.2-6 | Nonexistent fragment returns notFound error | PASS | PASS | PASS |
| 7.2-7 | Nonexistent service returns notFound error | N/A | PASS | PASS |
| 7.2-8 | Invalid DID URL returns invalidDidUrl error | PASS | PASS | N/A |
| 7.2-9 | Service fragment returns Service object | N/A | PASS | PASS |

