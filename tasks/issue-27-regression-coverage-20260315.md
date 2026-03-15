Reopening this for one follow-up concern: the implementation changes look materially correct, but the regression coverage is still narrower than I’m comfortable with for closing the issue completely.

What I think is fixed:

- generated EC keys are compressed
- `ExistingKey` inputs are normalized before DID construction
- resolution now validates EC point shape instead of checking length only

What is still missing:

- the new regression coverage is strongest on the `P-256` path
- I do not see equivalent targeted regression cases for:
  - `P-384` external uncompressed `ExistingKey` normalization
  - `secp256k1` external uncompressed `ExistingKey` normalization
  - malformed-but-correct-length `P-384` point rejection
  - malformed-but-correct-length `secp256k1` point rejection

That means the code may be fixed, but the issue is not well-defended against regression across all affected EC key types. I’m reopening it so the close condition includes coverage for the full affected surface, not just the first curve that was tested.
