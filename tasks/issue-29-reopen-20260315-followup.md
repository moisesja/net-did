Reopening this because the implementation is much closer now, but it still does not fully implement the DID Resolution service dereferencing algorithm.

What is fixed:

- `serviceType` filtering is implemented
- default service dereferencing now returns a DID Document with filtered services
- `text/uri-list` handling supports URI endpoint sets
- `verificationRelationship` is represented in the public API for fragment dereferencing
- RFC 3986 `relativeRef` handling is much better than before

What is still not fixed:

- unsupported `Accept` values still do not return `representationNotSupported`
  - per the DID Resolution algorithm, the service-query branch must:
    - return a filtered DID Document when `Accept` is missing or is a DID-document representation
    - return `text/uri-list` when that media type is requested
    - otherwise return `representationNotSupported`
  - the current code returns a filtered DID Document for any non-`text/uri-list` media type:
    - `src/NetDid.Core/Resolution/DefaultDidUrlDereferencer.cs:126-128`
- service-id matching still does not resolve relative references to absolute URIs before comparing
  - the spec requires relative service ids and relative `service=` parameter values to be resolved before matching
  - the current matcher only checks exact string equality or raw fragment equality:
    - `src/NetDid.Core/Resolution/DefaultDidUrlDereferencer.cs:149-160`

Why this still matters:

- a request like `Accept: text/plain` should not succeed with a DID Document result
- a DID Document containing `service.id = "#svc"` should match a query using the corresponding absolute DID URL, and vice versa
- both of these are algorithm-level behavior, not just optional polish

The current regression tests cover the major improvements, but I still do not see coverage for:

- unsupported `Accept` values returning `representationNotSupported`
- relative `service.id` and `service=` normalization to absolute URIs before matching
