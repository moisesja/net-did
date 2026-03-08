# Dereferencer cannot resolve embedded verification methods by fragment

## Summary

`DefaultDidUrlDereferencer` only looks for fragments in top-level `verificationMethod` and `service` arrays. Embedded verification methods inside relationship properties are ignored.

## Affected code

- `src/NetDid.Core/Resolution/DefaultDidUrlDereferencer.cs:55-61`
- `src/NetDid.Core/Resolution/DefaultDidUrlDereferencer.cs:105-132`

## Why this matters

The model explicitly supports embedded verification methods via `VerificationRelationshipEntry.FromEmbedded(...)`. A DID URL that points at one of those resources should dereference successfully. Today it returns `notFound`, which breaks standards compliance and any consumer that expects embedded-key dereferencing to work.

## Reproduction

1. Resolve a DID document whose `authentication` contains an embedded verification method with ID `did:example:123#embedded`.
2. Call `DefaultDidUrlDereferencer.DereferenceAsync("did:example:123#embedded")`.
3. Observe `DereferencingMetadata.Error == "notFound"`.

Minimal setup:

```csharp
var doc = new DidDocument
{
    Id = new Did("did:example:123"),
    Authentication =
    [
        VerificationRelationshipEntry.FromEmbedded(new VerificationMethod
        {
            Id = "did:example:123#embedded",
            Type = "Multikey",
            Controller = new Did("did:example:123"),
            PublicKeyMultibase = "z6Mkexample"
        })
    ]
};
```

## Expected behavior

- Fragment dereferencing should search all dereferenceable resources in the DID document, including embedded verification methods.

## Actual behavior

- `FindByFragment` ignores `authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, and `capabilityDelegation` when those entries embed full verification methods.

## Suggested fix

- Extend fragment lookup to inspect embedded methods in all verification relationships.
- Add dereferencing tests that cover embedded VMs in each relationship array.
