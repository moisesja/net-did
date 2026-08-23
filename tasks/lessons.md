# Lessons

- A derived-service dedup check and the dereferencer that selects that service must accept the
  same identifier spellings. If Core normalizes a bare selector such as `files` to `#files` but a
  method projection recognizes only relative/absolute fragment forms, it emits two services for
  one normalized id. Centralize or mirror the equivalence set, test every accepted spelling, and
  canonicalize compatibility artifacts to the target method's normative form. Separately, when a
  reviewer proposes changing a spec error code, check the method-specific algorithm before the
  generic registry: did:webvh v1.0 explicitly mandates `invalidDid` for an unsupported path/WHOIS
  endpoint scheme even though generic DID Resolution defines `invalidDid` more narrowly. (PR #142
  review round 1.)

- An optional cache must not change the default-off path's peak retention. If validation always
  materializes a cacheable raw representation and appends it unconditionally, the feature can hold
  large wire strings for the full traversal even when no cache will be written. Allocate the raw
  history collector only after the opt-in and finality capability succeed, retain only blocks at or
  below the finalized watermark, and enforce the raw aggregate budget while collecting rather than
  only during the later cache-write copy. (Issue #118 adversarial review.)

- Do not ask for plan approval for PR reviews. Reviewing a PR is read-only analysis plus the explicitly requested GitHub review/comment action, not source implementation; inspect, validate, and post the review directly.
- When the user corrects or narrows a request mid-thread, restate the corrected scope explicitly in the next work pass and revalidate only that scope before taking issue-tracker actions.
- CLAUDE.md "Plan First" / "Verify Plan" means: for any non-trivial task (≥3 steps or architectural decisions), write the plan to `tasks/todo{timestamp}.md` AND present it to the user for approval BEFORE editing any source files. Writing the plan file is not the same as getting approval — use `EnterPlanMode` / `ExitPlanMode` (or an explicit "OK to proceed?" check) and wait for a yes. A user constraint like "stay on this branch" is a scope guardrail, not approval to skip the plan-review step.
- A crypto→NetCrypto-style migration is a project-wide *public-API type-namespace swap* (`KeyType`/`ISigner` move from `NetDid.Core[.Crypto]` to `NetCrypto`), NOT a folder delete. The types flow through public DID-method signatures across src + samples + ALL test projects, so it must be one atomic pass — a piecemeal "Phase 1 warm-up" cannot compile in isolation: while net-did's types still exist, adding `using NetCrypto;` alongside `using NetDid.Core.Crypto;` makes `KeyType`/`DefaultKeyGenerator`/etc. ambiguous (CS0104). Correct order: delete the in-repo sources FIRST (removes the collision), THEN swap usings, THEN build-iterate.
- zsh does NOT word-split unquoted `$var` like bash. `perl -i -pe '...' $files` passes the whole newline-joined blob as one argument ("File name too long"). Use `find … -exec perl -i -pe '…' {} +` (and exclude `obj/`/`bin/`) for bulk in-place edits.
- When a test reaches an `internal` method that moved to NetCrypto (e.g. `DefaultCryptoProvider.DecompressEcPoint`), don't delete the whole test — re-express it against a public path. `JwkConverter.ToPublicJwk(keyType, compressedKey)` expands a compressed SEC1 point to X/Y; `Base64UrlEncoder.DecodeBytes(jwk.X/.Y)` recovers the coordinate bytes.
- Conformant Data Integrity (`eddsa-jcs-2022`, DataProofsDotnet) signs `SHA-256(JCS(proofConfig)) ‖ SHA-256(JCS(document))` — the **proofConfig (verificationMethod, created, proofPurpose, type, cryptosuite) is part of the signed bytes**, unlike net-did's old document-only signing. Consequences when migrating: (1) a proof field like `verificationMethod` can no longer be edited after signing (a test that stripped the `#fragment` post-hoc had to re-sign with the stripped form instead); (2) on verify, pass the wire `created` string **verbatim** (no `DateTimeOffset.Parse`/reformat) or the recomputed proofConfig won't match; (3) `CreateProofAsync` **requires** `proofOptions.VerificationMethod` (net-did used to auto-derive it) — set `did:key:{mb}#{mb}` explicitly.
- The DID-method-aware proof-signer parser (did:key URL → multibase, with the DID==fragment anti-spoof check) has **no home upstream** — DataProofsDotnet's dependency direction forbids DID parsing. Keep it in net-did (relocated to an internal `NetDid.Method.WebVh` helper) and feed the extracted multibase to `PublicKeyMaterial.FromMultikey`.
- A timeout/limit knob layered on top of a framework default must turn in BOTH directions.
  `HttpClient.Timeout` (100s default) enforces itself via its own internal linked token, so a
  per-request CTS knob can shorten but never lengthen the effective timeout — a configured value
  above 100s silently still caps at 100s. When adding such a knob, neutralize the hidden default on
  resources the library owns (`Timeout.InfiniteTimeSpan` on both the owned fallback client and the
  DI `ConfigureHttpClient` path), leave caller-injected resources untouched, and add a test for the
  raise-above-default direction, not just the lowering one.
- Security restrictions that intentionally remove a previously tested workflow are breaking
  changes even when they are secure-by-default fixes. Document every affected public path, whether
  customization can bypass the restriction, and the supported replacement workflow.
- Map malformed content only at the trust boundary that consumed it. A fetched did:webvh log with
  an invalid timestamp is `invalidDidLog`; catching that parse failure locally avoids relabeling
  unrelated format errors or changing Create/Update exception contracts.
- "Take it as far as possible without prompting" does NOT extend to merging PRs into main.
  Opening the PR is the autonomous boundary; the user reviews and merges (or explicitly says
  "merge it" per-PR). Plan-approval of a step that says "merge on green CI" is still weaker
  than the user's standing review gate — pause at the PR and hand off.
- Writer/reader parity inside one library is NOT spec conformance. Before publishing a
  security contract about a spec-governed format, verify the claim against the NORMATIVE
  spec text (fetch the spec source; quote the rule). did:webvh v1.0 authorizes a
  pre-rotation entry with the CURRENT entry's own updateKeys — the prior-keys rule only
  holds when pre-rotation is inactive. NetDid deviated and my #91 evidence contract
  ("keys authorized to sign the next entry") repeated the deviation as a promise (#93).
- `JsonDocument.Parse` (default options) ACCEPTS duplicate JSON members and keeps the LAST one.
  For a spec-governed format where "every supplied X is validated" is the security contract, a
  decoy duplicate (`"proof":[{bogus}],"proof":[valid]`) smuggles an unvalidated member past the
  check. Parse untrusted document JSON at the trust boundary with
  `new JsonDocumentOptions { AllowDuplicateProperties = false }` (recursive; catches nested dups)
  and map the `JsonException` to the format's invalid-content error. (Issue #101 PR review.)
- Do NOT "preserve and accept" arbitrary members of a signed structure you do not evaluate in the
  name of interop. Accepting a Data Integrity proof carrying `previousProof`/`expires`/`id`/`domain`
  you never resolve/enforce is a FALSE validation claim (dangling chain refs, elapsed expiry pass
  silently). For a narrow method profile (did:webvh controller proof = type/cryptosuite/
  verificationMethod/created?/proofPurpose/proofValue), REJECT any out-of-profile member. Then the
  modeled fields are the whole proof, verification is byte-faithful, and no raw-JSON carry is
  needed. "Fully interoperable" means interoperating with what the method actually emits, not
  accepting every superset the base spec permits. (Issue #101 PR review.)
- A dedup/identity key that joins nullable strings is unsound: `Created ?? ""` folds absent
  (`null`) and present-empty (`""`) — DISTINCT signed configs — to one key, and a shared separator
  can be injected by field contents. Use a value TUPLE
  (`HashSet<(string, string, string, string?, string, string)>`) so components compare
  independently and `null != ""`. A string-join identity over attacker-controlled fields is a
  collision waiting to skip a distinct invalid item behind a valid one. (Issue #101 PR review, F1.)
- An arbitrary count cap (e.g. "max 100 proofs") that rejects otherwise schema-valid input is a
  baseless compatibility break, not a DoS control. Bound work by structure instead: stop at the
  first failing item, and dedup byte-identical items (verify once). With deterministic Ed25519
  (one key ⇒ one valid signature over a fixed message), distinct passing proofs ≤ active keys, so
  no cap is needed and no conforming log is rejected on count. (Issue #101 PR review, finding 3.)
- After a reworked fix that materially changes the design (removing a field, adding a trust check),
  re-run the FULL adversarial review on the NEW surface — do not assume the prior clean verdict
  carries over. The rework's own new dedup introduced a fresh soundness bug the second pass caught.
- Do NOT hand-roll a subset of a complex signed-format algorithm (W3C Data Integrity: type/suite/
  purpose/expires/previousProof-chains). Delegate verification to the library that owns it
  (DataProofsDotnet's `DataIntegrityProofPipeline`) and contribute only the method-specific POLICY
  via an `IVerificationMethodResolver` (did:key anti-spoof + updateKeys membership + assertionMethod),
  plus `ProofVerificationOptions` (ExpectedProofPurpose, VerificationTime=versionTime for the
  expires policy). Re-implementing DI semantics piecemeal produced three rounds of review findings
  (issue #101 / PR #102). Feed the pipeline the entry serialized WITH full-fidelity proofs; an
  entry-hash check already runs before proof validation, so the non-proof content is proven
  byte-faithful to the signed bytes.
- A "deterministic Ed25519 ⇒ one valid proof per key" work bound is FALSE: eddsa-jcs-2022 signs the
  whole proof configuration, and `created` is attacker-chosen, so one key mints unlimited distinct
  valid proofs by varying `created`. Never derive a work bound from signature determinism over a
  mutable message. Bound verification with an explicit, documented, configurable resource budget
  (proofs per entry) over an already size-capped fetch. (Issue #101 PR review round 2.)
- A JSON-Schema field list that is "required at minimum" with additionalProperties OPEN means extra
  members (`id`, `expires`) are CONFORMING; rejecting them is an interop regression, not hardening.
  Preserve and VALIDATE them (or document a deliberate, labeled limitation) — do not silently reject
  and call it "the profile." (Issue #101 PR review round 2, reversing my own round-1 narrowing.)
- Map JSON-ACCESS failures at the parse trust boundary, not just JsonException. `JsonDocument.Parse`
  accepts a token like `"\uD800"` but `GetString()` throws `InvalidOperationException` on decode; a
  `catch (JsonException)`-only boundary lets it escape to `notFound`. Catch the JSON-access set
  (`InvalidOperationException`/`KeyNotFoundException`/`OverflowException`/`ArgumentException`/
  `JsonException`) → the format's invalid-content error. (Issue #101 PR review round 2, F3.)
- Treat caller-supplied interface-typed collections (IReadOnlyList<T> etc.) as adversarial
  code at trust boundaries: an implementation can return different contents per
  enumeration (TOCTOU). Snapshot ONCE at entry and use the private copy for validation,
  comparison, hashing/signing, serialization, and reported evidence. A post-return
  defensive copy alone only fixes the last read. Adversarial review must model hostile
  implementations of interfaces, not just mutation of concrete List<T>.
- Document security postconditions in their exclusive/complete form: membership checks
  ("new key present, retired key absent") admit supersets with unexpected extra keys;
  exclusive rotation requires set-equality against the intended post-rotation set.
- When the user confirms that the checkout or branch changed between planning and approval,
  re-baseline branch, HEAD, status, and diff before editing; do not carry dirty-worktree
  assumptions from the planning turn into implementation.
- Before implementing significant or breaking work from `main`, create a dedicated issue branch
  immediately after plan approval and before the first source edit; re-baselining `main` is not a
  substitute for establishing the implementation branch.
- Preserve-mode / "carry the previous value forward" is a fidelity trap for a signed format.
  did:webvh Update with `NewDocument == null` took `previousEntry.State` (the TYPED model) into a
  freshly built head entry, which re-serialized through the lossy `DidDocumentSerializer` and
  silently DROPPED signed nested members the model doesn't surface (e.g. `verificationMethod[i].x-ext`
  — `VerificationMethod` has no `AdditionalProperties`; only `DidDocument`/`Service` do). The head is
  then hashed/signed over the reduced state, so the erasure is invisible. Round-3 fixed republished
  PRIOR entries via whole-entry wire provenance but missed the NEW head. Fix: a second
  `ConditionalWeakTable<DidDocument, WireState>` keyed by the parsed document reference re-emits the
  raw state verbatim while a modeled fingerprint still matches; a `with`-clone (new ref) or a
  model-visible mutation falls back to modeled. A fingerprint over a LOSSY serialization does NOT bind
  model-invisible members — sound only because the sole provenance-registered doc reaching a signed
  head is the internal parsed `previousEntry.State` (no caller reference), and a supplied `NewDocument`
  is deep-copied to a fresh unregistered reference. State the guard's precondition as "model-visible
  change", not "any change". (Issue #101 PR #102 final adversarial round, F1.)
- Snapshot the caller's DID DOCUMENT once at the update trust boundary, not just the parameter
  collections. `DidDocument` holds interface-typed collections (`IReadOnlyList<>`,
  `IReadOnlyDictionary<string,JsonElement>`); a hostile implementation returns different contents per
  enumeration, and Update reads the document across an `await` (hash → sign → publish → did.json →
  reported result), so the published bytes can diverge from the signed bytes. `SnapshotDocument` =
  `Deserialize(Serialize(doc, JsonLd))` materializes concrete collections; every downstream stage,
  including the `Id == did` binding check, uses the private copy. Even when an inner serializer
  enumerates a field twice, the snapshot is discarded intermediate output — the frozen concrete copy
  is what everything after reads, so hash == publish by construction. (Issue #101 PR #102 F2.)
- Enforce a spec's "every entry" identity invariant at the ONE chain-validation choke point, not in a
  branch. did:webvh v1.0: the SCID segment of `state.id` MUST equal `parameters.scid` "for every
  entry's state.id, not just the first ... independently of portability" (only host/path may change).
  NetDid checked `State.Id == did` on the TARGET only and ran a per-entry `HasConsistentScid` helper
  solely in the deactivated-tail metadata branch, so a genuinely signed middle/genesis entry with a
  foreign SCID resolved. Fix: one `ValidateStateScidConsistency` call for genesis + every subsequent
  validated entry inside `ValidateChainWithPerEntryParams` — resolution maps it to `invalidDidLog`,
  and Update/Deactivate inherit writer parity through the same `ValidateChain`. Compare SCID-level
  (keeps portable renames valid), pin the method with `StartsWith("did:webvh:")` (ExtractScid alone
  returns a segment for sibling methods like `did:webvhevil:`), and reject empty/missing/malformed
  ids. Moving the check ahead of a later `ArgumentException` identity binding changes the thrown
  exception TYPE for forged logs (now `LogChainValidationException`) — update the pinning tests and
  note it in the CHANGELOG. (Issue #101 PR #102 F3.)
- Adversarial subagents that run `git stash`/`git checkout` to test pre-fix behavior can CLOBBER the
  working tree they were told to review: a `git checkout -- <tracked file>` reverted my uncommitted
  test edits (an added test + two assertion changes) while leaving untracked new files alone, and the
  stash list came back empty. After any adversarial pass that reports "tree restored to WIP" or
  "reverted my changes", re-run `git diff --stat` and the FULL suite before trusting green — a
  dropped edit reads as a passing baseline. Prefer giving review agents a read-only worktree, or
  re-verify the diff is intact afterward. (Issue #101 PR #102 final adversarial round.)
- The ≥3-steps non-triviality test counts the WHOLE task workflow (tests, verification,
  adversarial review, PR), not the size of the source diff. A two-line fix driven through the
  full issue-fix cycle is non-trivial and requires plan approval BEFORE the first edit. Neither
  a maintainer-authored issue that prescribes the exact fix, nor an "operating autonomously"
  session mode, waives the plan-approval gate — autonomy governs how to work within the
  workflow, not whether its gates apply. Do not invent carve-outs to skip approval; when in
  doubt, present the plan and wait. Corollary (same thread): the gate is a BEFORE-work gate —
  once the work is done and corrected, do not stage a retroactive approval pause on simple
  remaining steps; acknowledge, capture the lesson, and finish.
- A DoS bound on untrusted-remote traversal must cover COUNT *and* aggregate BYTES *and*
  aggregate WALL-CLOCK — a count-only cap is byte- and time-blind. did:ethr resolution added
  a hop cap + event-count cap, but an adversarial re-attack showed: (a) one large-value
  attribute event per hop stays under the count cap yet retains ~response-cap bytes/hop →
  multi-GB heap OOM; (b) the VersionTime path fanned out one `eth_getBlockByNumber` per event
  with no overall deadline (and `versionTime` is attacker-supplyable via the DID-URL query);
  (c) hops × per-request timeout = hours. Fix all three with ONE coherent pass: an aggregate
  retained-byte budget (32 MiB), an overall resolution deadline via a linked CTS spanning the
  whole walk + post-walk fan-out (when the DEADLINE token fires, `ct.IsCancellationRequested`
  is false so it maps to notFound instead of propagating), and realistic count caps. A
  per-request cap does NOT imply an aggregate cap. (PR #104, did:ethr adoption of #70.)
- Adopting a fork PR of a whole new subsystem is NOT just conflict resolution — the adopted code
  becomes ours and needs the full gate. Here the crypto swap reviewed clean but the trust-boundary
  lens found 5 pre-existing CONFIRMED issues (1 CRITICAL) in the contributor's resolver, and a
  re-attack found 3 more residuals in our own fixes. Run `adversarial-review` on the ENTIRE adopted
  diff (worktree-isolated agents), and re-attack the fixes — the first fix pass often has a deeper
  residual (count caps → aggregate caps). Converge when residuals collapse to one inherent, DOCUMENTED
  trust property (a single untrusted RPC endpoint can forge a self-consistent history — integrity, not
  availability), not to "no more findings". Preserve the original author's commits (merge, don't squash)
  so credit survives when the superseding PR lands. (PR #104 adopting #70 by @mirceanis.)
- A Core serializer change ripples through EVERY method's round-trip and any fingerprint
  built on modeled serialization — run the FULL suite, not just the method you're targeting.
  Fixing VerificationMethodJsonConverter.Read to capture AdditionalProperties (so did:ethr's
  publicKeyHex round-trips) changed did:webvh's #101 state-provenance fingerprint (which hashes
  the modeled serialization), breaking one LogEntryWireProvenanceTests assertion. When a
  security-property test breaks after an unrelated-looking change, DON'T just make it pass:
  determine whether the property was WEAKENED or the test's proxy became OUTDATED. Here the
  fingerprint became strictly more faithful (models more members → detects more changes → drops
  fewer signed members), which strengthened #101; the test's "modeled fallback drops VM members"
  proxy was the outdated part. Verify the fingerprint is computed consistently at parse- and
  serialize-time before concluding "safe", and record the cross-cutting effect in the commit +
  PR reply so the reviewer sees why their #101 test changed. (PR #104 review round.)
- "Avoid whack-a-mole" means closing residuals the reviewer's own comment already hinted at,
  even when they sanctioned a simpler option. The #1 fix could use stable-sort-by-block OR
  (block, logIndex); the reviewer listed logIndex first. I shipped stable-sort, then the
  adversarial re-review flagged that it trusts intra-block response order — exactly the gap
  logIndex closes. Doing the logIndex sort proactively (before re-review) would have saved a
  round. When a reviewer lists two options and one is strictly more robust, prefer the robust
  one unless it is materially more work. (PR #104 review round.)
- A security fix is complete only when it closes the invalid-state CLASS, not the one fixture
  named in a review. For untrusted ordered inputs, test mixed valid+invalid batches as well as
  all-invalid batches; require presence, syntax, and uniqueness of ordering metadata; validate
  source/identity/block invariants at the same choke point; and reject invalid selector syntax
  before external I/O. In PR #104, accepting one good event beside a malformed revoke, defaulting
  a missing `logIndex` to zero, and treating malformed historical options as "latest" were all the
  same fail-open pattern. Build the negative-state matrix before implementation, then re-attack
  the whole matrix after the fix to avoid reviewer/fixer whack-a-mole.
- Do not impose strict monotonicity on a lower-resolution projection of an ordered clock without
  proving the projection preserves strictness for every supported backend. Aurora feeds a
  nanosecond NEAR timestamp to the EVM but exposes `TIMESTAMP` in whole seconds, so distinct ordered
  blocks can legitimately compare equal. For historical prefix selection, block number supplies
  order: require timestamps to be non-decreasing and reject only a decrease. Pair the negative
  regression with an equal-value positive case so "hardening" cannot become honest-input denial.
- At an untrusted wire boundary, distinguish a schema-optional member from a malformed present
  member. Ethereum's canonical Log schema makes `removed` optional: absence is compatible with a
  canonical log, while explicit `true` must be rejected and explicit `null`/non-Boolean values are
  malformed. Do not turn an optional advisory flag into a required compatibility gate unless the
  protocol defines omission as unsafe; a hostile provider that omits it could already lie with
  `false`.
- When a dependency's public API is the thing blocking a feature, ask whether the fix belongs
  UPSTREAM before designing a local workaround. did:ethr needed recoverable secp256k1 signing
  over a caller-computed digest; `ISigner` cannot express it (it SHA-256-hashes internally and
  returns no recovery id). My plan defined a net-did-local `IEthereumDigestSigner` — the user
  asked "Can the ISigner issue be fixed upstream? Should it?" and the answer was yes on both:
  NetCrypto already owned the primitive (`Secp256k1Recoverable`), so the abstraction belonged
  next to it, and a local interface would have forked the signer ecosystem (an HSM/key-store
  key would work for did:webvh but not did:ethr). The test for "upstream vs local": does the
  dependency already own the primitive, and would a local interface force other consumers to
  reimplement it? If yes to either, file it upstream. Keep the boundary the upstream library
  documented — NetCrypto's FR-12 ruling puts keccak and EVM v-encoding in the wallet layer, so
  those stayed in net-did.
- "Filing an issue" and "implementing the fix" are separate asks across repo boundaries. When
  a cross-repo dependency appears mid-task, propose the split and let the user choose who
  implements — here the user said "I will fix the crypto-dotnet library separately. Just file
  the issue with as much detail as possible along with justification." A cross-repo issue is a
  SPEC handoff, not a bug report: include the exact proposed API, the implementations and their
  input contracts, the boundary it must not cross, the test matrix, the chores (PublicAPI.txt,
  CHANGELOG, version), and — most importantly — the JUSTIFICATION for why it belongs there
  rather than downstream. Then keep building everything that doesn't depend on it and mark the
  blocked phases explicitly.
- A dev node is NOT a conformance oracle for consensus rules. Anvil accepts high-S signatures
  and wrong-chain-id transactions that mainnet consensus rejects, so negative tests for EIP-2
  low-S and EIP-155 replay protection FAIL against Anvil while passing against a stricter
  in-memory emulator. Split the oracles deliberately: the real node proves contract semantics
  and calldata/bytecode correctness; the emulator proves consensus-grade validation. Say which
  oracle covers which class in the test file, or a later reader will "fix" the strict one to
  match the permissive one.
- Wall-clock-boundary assertions need slack on a real chain. ERC-1056 revocation sets
  `validTo = block.timestamp`, and the JS-compatible resolver keeps an entry while
  `validTo >= now`, so a revocation only takes effect the NEXT whole second. Against an
  emulator with a controllable clock this is invisible; against a live node the assertion is
  flaky until you step the clock past the boundary. When a spec's validity comparison is
  inclusive, either advance the clock explicitly or assert after the boundary — never assume
  "the write landed" means "the effect is visible".
- A NORMATIVE SPEC CAN BE WRONG ABOUT ITS OWN DEPLOYED CONTRACT — verify security claims
  against the artifact that enforces them, not only the prose. The did:ethr spec states that
  deactivation via `changeOwner(0x0)` "is irreversible" and that "no further changes to the DID
  document are possible". The deployed ERC-1056 registry does not enforce that: `identityOwner()`
  is `owner != address(0) ? owner : identity`, so zeroing the owner slot returns control TO THE
  IDENTITY ADDRESS. An EOA identity whose key survives can write again, and a later non-zero
  `DIDOwnerChanged` clears the `deactivated` flag entirely. I had copied the spec's claim into
  README, the PRD, XML docs, and a sample comment. The earlier lesson said "verify the claim
  against the NORMATIVE spec text"; this extends it: when the spec describes what a piece of
  code does, the code is the higher authority. Read the contract/reference implementation, and
  when they disagree, document the OBSERVED behavior and name the divergence.
- A mock that is wrong in a security-relevant direction does not just miss bugs, it MANUFACTURES
  false conclusions. The chain emulator transcribed `identityOwner` as a plain dictionary lookup
  instead of the contract's zero-means-self rule. Offline, deactivation therefore looked like a
  permanent lock — and a second red-team agent, reasoning against that emulator, reported
  "post-deactivation write REJECTED", the exact opposite of what real bytecode does. Two
  defences: (1) transcribe contract logic line-by-line from the source and cite it in a comment,
  never paraphrase from memory; (2) run at least one DIFFERENTIAL test per security-relevant
  behavior — same scenario against the mock and against the real thing — because a mock's errors
  are invisible to every test that uses only the mock.
- Fixing a finding can encode the same misconception in a new place. Round 1 "fixed" the
  zero-owner case by reporting an EMPTY set of effective update keys ("nobody can update"),
  which was just the permanence myth in another form; the correct answer is the identity address.
  When a fix asserts something about the world rather than about the code, re-derive it from the
  authority (here: read the owner back from the chain) instead of hard-coding the conclusion.
- Scope a security refusal to the vulnerable operations, not the vulnerable-looking situation.
  The legacy ERC-1056 nonce divergence only breaks owner/delegate meta-transactions (their
  preimage reads a slot nothing increments); attribute meta-transactions read the slot that IS
  incremented and stay single-use. My first guard refused all meta-transactions once ownership
  had moved, which broke a legitimate, demonstrably-safe path — caught by an existing test
  failing. A guard that denies honest input is a defect too; derive the predicate from the
  mechanism, not from the scenario in the exploit report.
- Validate BOTH halves of a name/value pair at a write boundary. Round 2 rejected non-ASCII
  attribute NAMES (the resolver decodes ASCII) but left VALUES unchecked, so writing the
  spec-canonical `did/pub/Secp256k1/veriKey/hex` with a non-key value landed on-chain and then
  threw inside the document builder — resolution returned notFound for the ENTIRE DID, for the
  attribute's 10-year validity. One API call permanently bricked the identity. Two rules: (a)
  when you harden one field of a structure, enumerate the sibling fields that reach the same
  consumer; (b) a per-entry decode failure must degrade THAT ENTRY, not the whole document —
  fail-closed belongs to authorization/history integrity, not to one optional key's encoding.
  The tolerant read is also the interoperable one: an attribute another tool wrote that we
  cannot decode should not erase a DID we can otherwise resolve.
- A `try` block that wraps "the risky part" leaves the epilogue unguarded, and fixes tend to
  RELOCATE that gap rather than close it. The landed-transaction evidence fix wrapped the
  submission loop; the very same fix then ADDED a post-loop chain read, so a malformed response
  there — plus cancellation before it, plus a resolve failure — reported "nothing landed" while
  transactions sat on-chain. When the invariant is "after side effects begin, every exit path
  carries the evidence", the guard must span from the first side effect to the return, not
  around the loop that produces them.
- Report the effect, not the bookkeeping. The hash-echo verification threw AFTER
  `eth_sendRawTransaction` had already accepted the bytes, so the operation never reached the
  landed list even though the chain applied it — the evidence was not merely missing but WRONG,
  which is worse: a caller trusting it double-applies on retry. Record a side effect at the
  moment it becomes possible (broadcast), not at the moment you finish validating the response.
- Two ceilings on two node-controlled factors do not bound their product. Capping gas PRICE at
  5,000 gwei and gas LIMIT at 3M still authorized 15 ETH per transaction. Bound the quantity the
  user actually cares about — total fee — not only its inputs; a per-factor cap reads like
  protection while leaving the real exposure at the product of the caps.
- Strictness that a legitimate backend cannot satisfy is a defect, not rigor. Rejecting high-S
  signatures looked like sound EIP-2 hygiene but broke every HSM whose PKCS#11 `CKM_ECDSA` does
  not normalize — contradicting the same change's "HSM keys work" claim. The malleable twin is a
  valid signature over the same digest recovering to the same key, so canonicalize (s' = n-s,
  flip recid) instead of refusing. Before adding a validity check on data from a pluggable seam,
  ask which real implementations produce the form you are about to reject.
- `Exception.Data` on an exception thrown by a pluggable dependency is UNTRUSTED INPUT, not an
  internal side channel. Reserved-looking string keys provide no provenance: an injected RPC
  client used them to forge a "confirmed" transaction before any receipt existed and suppress
  the real local candidate hash. Carry security-relevant lifecycle state in a private typed
  object owned by the pipeline, bind receipts back to the locally computed request hash at the
  outer trust boundary, and only then project sanitized evidence onto the public exception.
- A deadline is not an overall bound if it starts after pre-flight or merely passes a token to
  an injectable implementation. Start the clock before the first awaited dependency and apply
  the bound to the returned task (`WaitAsync`), so an implementation that ignores cancellation
  cannot hang the operation. When mapping cancellation, prove WHICH token fired; a spontaneous
  dependency `OperationCanceledException` is not evidence that the internal deadline elapsed.
- Typed side state is not enough if the final projection still writes into a dependency-owned
  exception. `Exception.Data` is virtual; a custom RPC exception can throw from its getter or
  expose a read-only dictionary, replacing the real failure exactly when the locally computed
  hash must escape. Fold typed state first, then project it onto a fresh library-owned exception
  with known-writable metadata; retain the hostile exception only as the inner cause.
- Treat the whole dependency exception as untrusted, not only its `Data`: `Exception.Message`
  is virtual too. A custom transport exception that threw from `Message` defeated the first
  fresh-carrier fix before evidence could be attached. Carrier construction must use fixed
  library-owned text (or text from an exact known-safe type) and retain the dependency exception
  opaquely as `InnerException`; diagnostic formatting must never be on the evidence-critical
  path.
- Commit the real fix BEFORE any revert/mutate/restore dance. `git checkout <file>` restores
  the last COMMITTED state, so restoring after a mutation run clobbers an uncommitted fix in
  the same file (the #109 dedupe fix vanished this way; caught only because `git diff --stat`
  was re-checked afterwards, per the existing clobber lesson). Sequence: commit fix → mutate →
  run → `git checkout` restore → verify diff intact.
- Do not serialize PR-opening behind an adversarial RE-ATTACK of a fix the finder itself
  already validated. Round-1 findings gate the PR; a round-2 re-attack on a Low-severity,
  probe-validated rework can land as a PR comment (and a follow-up commit if confirmed)
  instead of blocking the open PR — the user pinged "taking too long" exactly here. Post the
  PR, let the re-attack arrive asynchronously, fix on the branch.
- A `static` lambda stops CLOSURE capture, not EXECUTION-CONTEXT capture. `ContinueWith`
  (and awaiter registration generally) snapshots the current ExecutionContext, so a
  long-lived/permanent continuation silently pins the registering request's AsyncLocal graph
  (HttpContext, Activity baggage, credentials) for the antecedent's lifetime. Register
  observers/monitors under `ExecutionContext.SuppressFlow()` (guard `IsFlowSuppressed` for
  already-suppressed callers) and pin with an AsyncLocal-payload + WeakReference test that
  keeps the antecedent ROOTED while asserting the payload is collectible. (PR #113 review.)
- Attach recovery/bookkeeping state only when the failure mode it serves can actually occur,
  not eagerly on every call. The eager observer put a table insert + continuation on paths
  that can never abandon (completed tasks — the in-memory signer's every write). Structure:
  fast-path out states where the hazard is impossible, and attach in the code path where the
  hazard materializes (the cancellation catch). Pin hot-path cost DIFFERENTIALLY against the
  bare primitive so the baseline cancels out of the assertion. (PR #113 review.)
- `GC.GetTotalMemory` is a process-global oracle — invalid under parallel test runners.
  Count the specific resource on the specific object (reflection into the continuation slot,
  failing loudly if the BCL field moves) or use WeakReferences. And an "unobserved fault does
  not escalate" assert is only probative if the faulted task is COLLECTIBLE when finalization
  is forced — scope ownership into a helper frame; a rooted task never escalates regardless.
- A lexical source guard must be whitespace-tolerant AND pin the positive inventory
  (per-file expected call-site counts): banning `.WaitAsync(` alone misses `.WaitAsync (`
  and — worse — cannot see a DELETED wrapper, which silently un-bounds the await it guarded.
- Scale process to the change's severity, and never queue a SECOND blocking review round.
  A Low-severity test-harness/doc fix gets one adversarial pass at most; once its CONFIRMED
  findings are fixed and re-verified, OPEN THE PR — a re-attack of the rework lands as a PR
  comment + follow-up commit, not a gate. The user pinged "what takes so long" on issue #112
  (a harness ergonomics fix) exactly while a round-2 re-attack was being queued — the same
  failure mode as the earlier "taking too long" lesson, now from proportionality: ceremony
  (two agents, containerized oracles, doc sweeps) is justified by what the diff can break,
  not by the workflow's default shape.
- Bound the DEPENDENCY task at its own await site, not a wrapper task you created around
  your own state machine. Wrapping ResolveFromChainAsync (our task) in WaitAsyncObserved
  "returned control" on deadline but abandoned the inner machine at its bare
  `await rpc.X(...)` — one retained continuation per resolution on a shared hung
  dependency task, and a late completion resumed every abandoned machine into a
  post-deadline RPC fan-out. The existing "apply the bound to the returned task" lesson
  means the task RETURNED BY THE DEPENDENCY: wrap each rpc/signer await (the write path
  already did — symmetry with existing call sites was the tell). Prove it with a
  shared-TCS regression: N concurrent ops, continuation-slot count ≤1, late completion
  ⇒ zero further dependency calls. (PR #122 round 2.)
- Truncating attacker-controlled data AFTER materializing it is not a bound.
  `error.ToJsonString()[..1024]` first serialized the full node — default JSON-encoder
  escaping amplifies ~6x, so a near-response-cap error transiently allocated ~192 MiB
  before the slice. Bound at the point of EXTRACTION: read only the schema's scalar
  members (numeric code, ≤256-char prefix of the message string the DOM already holds),
  never serialize the hostile node. Generalize: for any cap, ask what has already been
  allocated/computed by the time the cap applies. (PR #122 round 2.)
- Exact runtime type is provenance ONLY for types hostile code cannot construct. A public
  exception type with a public ctor can be thrown by an injected dependency carrying
  arbitrary text, so `GetType() == typeof(PublicException)` does not make its Message
  trustworthy. For caller-facing diagnostics from a catch, publish fixed library-owned
  text and select the category via an internal sealed marker exception type
  (uninstantiable outside the assembly). And a guarded log call's FALLBACK needs its own
  guard: providers can throw on every Log call — logging must end in a final swallow to
  preserve a never-throw contract. (PR #122 rounds 1-2.)
- Do not claim current-spec conformance from memory of an older vocabulary: the W3C DID
  Resolution draft moved to RFC 9457 error OBJECTS (https://www.w3.org/ns/did#INTERNAL_ERROR
  type URIs, empty didDocumentMetadata on failure); the camelCase string codes this library
  uses are the legacy DID Spec Registries form. When staying on a legacy form deliberately
  (ecosystem compatibility, one-PR scope), say so explicitly in docs/PR and file the
  migration issue — a reviewer reading the current TR will otherwise refute the claim.
  (PR #122 rounds 1-2, issue #123.)
- "Bound the dependency await" has a THIRD leg: already-completed tasks. WaitAsync(Observed)
  deliberately lets a completed task beat a fired token, so a token-ignoring dependency
  returning COMPLETED tasks keeps the whole loop synchronous and the deadline never
  interrupts it — 1,000 post-cancel RPC calls in PR #122 round 3. A cancellation bound is
  three checks, not one: (1) wrap the pending task (WaitAsyncObserved), (2) observe/dedupe
  abandonment, (3) `ct.ThrowIfCancellationRequested()` before every dependency call and per
  loop iteration on the completed-task fast path. Test BOTH modes: shared-pending task AND
  completed-task fast path (cancel mid-loop ⇒ exactly one further call issued: zero).
- When a bounded-extraction design keeps failing review, switch from bounding the DATA to
  eliminating the READ. Extracting a "capped prefix" of an attacker string still (a)
  materializes the full decoded value first (JsonValue.TryGetValue<string> allocates all of
  it — the DOM holds UTF-8, not the decoded string), (b) forwards decoded control chars
  (CR/LF/ESC/U+2028) into logs, and (c) can split surrogate pairs. Only a value with an
  intrinsically bounded type (a JSON number via TryGetValue<long>) is safe to surface.
  Fixed diagnostic + numeric code = bounded by construction; three review rounds of caps
  and sanitizers were all dominated by simply not reading the member.
- Touching how a JsonObject/JsonNode member is ACCESSED changes which exceptions escape:
  lazy JsonObject materialization throws ArgumentException on duplicate keys, so replacing
  `node.ToJsonString()` (serializes raw, never materializes the dictionary) with
  `TryGetPropertyValue` INTRODUCED a raw JSON-layer escape at a boundary that promised
  EthereumInteractionException. Any switch between serialize-style and dictionary-style
  access on untrusted JSON needs the boundary catch re-checked and a duplicate-member test
  (envelope AND nested object).
- Guard placement must be SYMMETRIC around every dependency interaction, or the guard just
  relocates the hole to the terminal element (the existing "epilogue unguarded" lesson, now
  proven for loops): pre-call/loop-head token checks cannot observe cancellation that fires
  during the LAST call — there is no next iteration — so resolution returned a stale SUCCESS
  to a cancelled caller. The complete pattern per dependency await: check BEFORE the call,
  check AFTER the await (before parsing), check PER ITEM when materializing a
  dependency-owned collection (never bare .ToList() — a hostile enumerator is unbounded
  synchronous work), and one final check BEFORE the success return. Test matrix must include
  the terminal element of every loop and the single-call paths (changed()=0, final
  timestamp), in BOTH cancellation modes — a test whose hostile hop forces a second
  iteration validates only the loop-head check and hides the terminal bug.
- State honestly what a token-based bound can never do: it cannot preempt synchronous
  blocking inside an injected implementation (method body before returning its task, or a
  collection's MoveNext). Don't paper over it with wrappers — scope the claim ("hard bound
  against hostile NODES via the async default client; in-process hostile CLIENT
  implementations need process isolation") in the knob's doc, and update it the moment a
  reviewer shows the gap. Fail-first discipline applies to review-round fixes too: prove the
  new tests red on the pre-fix source — and expect a pre-fix HANG (not a failure) when the
  old bug is an unbounded loop; run that proof with a short timeout and without the hanging
  test in the batch.
- A cancellation check inside a `foreach` body does NOT cover the enumeration boundary:
  `MoveNext(false)` and enumerator `Dispose()` execute without entering the body. If either
  cancels the caller, an empty-result/error branch can win first and misclassify genuine
  cancellation. Check the token once more immediately AFTER enumeration, before sorting,
  empty checks, or other classification. Pin it with an iterator that cancels then
  `yield break`s, so the body is provably never entered. (PR #122 round-4 follow-up.)
- Local post-operation gates are still bypassed when dependency code CANCELS and then
  THROWS (for example, enumerator `Dispose()` cancels the caller and throws before the
  post-foreach check). At an async trust boundary whose contract says caller cancellation
  propagates, put a caller-token-priority catch filter before domain/generic mappings and
  call `ct.ThrowIfCancellationRequested()`. Pin the cancel-then-throw shape; testing only
  cancel-then-return leaves this race open.
- Reflection into `Task.m_continuationObject` observes a transient implementation detail,
  not an atomic steady-state snapshot. A canceled `WaitAsync` source continuation may
  briefly coexist with the one permanent deduped fault observer after the caller-visible
  task completes; PR #122 CI saw 2 while stress iteration 60 reproduced it locally. Poll
  for bounded cleanup before asserting the permanent count, with a short timeout that
  still fails a real retained-continuation leak. Never weaken the final ≤1 invariant.
- A shared metadata type does not imply one timestamp precision policy. `created` and `updated`
  can require canonical whole seconds while a method-specific `versionTime` uses authenticated
  fractional precision as part of version identity. Applying one lossy converter to all three
  can make serialized resolution metadata select a different historical version when reused.
  Also, instant equality does not prove UTC normalization for `DateTimeOffset`: assert the
  resulting `Offset` explicitly, and reject zone-less input before the runtime can interpret it
  using the resolver host's local timezone. (PR #126 review round 2.)
- A depth probe must target the OLDEST real data its consumer can legitimately need, and
  must issue the SAME query shape the consumer issues. The #119 endpoint probe used a
  2020-era mainnet event found by sampling 10k-block windows — which skipped the registry's
  actual first events at block 7,049,729 (2019) — so it approved endpoints that could not
  resolve real 2019 DIDs; and it queried a 41-block range while resolution queries exactly
  one block, so providers with tight range caps were rejected that resolution would have
  served fine. Establish "earliest" from an indexed source (explorer ascending scan), not
  window sampling, verify it via the consumer's own call shape, and pin both the datum and
  the shape with invariant tests. (PR #129 review round 2, findings 1-2.)
- RPC/service URLs are credentials: userinfo, provider project keys in the path, query
  tokens. Any log line that includes a caller-supplied URL — including SUCCESS paths —
  is a credential-disclosure channel. Log a sanitized label (scheme + host + non-default
  port); for unparseable input log only its position (unparseable means unsanitizable);
  pin with sentinel-secret tests across every outcome shape. "The caller supplied it" does
  not make it safe to persist in logs. (PR #129 review round 2, finding 3.)
- Fail-first evidence must FAIL ON AN ASSERTION, quickly and deterministically. A test that
  wedges/OOMs against pre-fix code (a NonTerminatingList enumerated by unbounded pre-fix
  snapshotting "failed" only via ~45 s memory-pressure death) is not reproducible evidence
  and can hang the suite on bigger machines. Design the hostile double so the pre-fix
  outcome is a fast, clean failure (throw-on-first-access to prove "never touched"; a
  finite Max+N sequence to prove cap semantics); keep genuinely infinite adversaries out
  of in-process test runs. (PR #129 round 3, finding 5.)
- Before claiming "same request/query shape as <component>", diff against that component's
  ACTUAL request field-by-field — block range AND every topic position AND address. The
  probe claimed resolution's shape after matching only the block range; resolution also
  sends a topic0 signature OR-list, and a wildcard topic0 is a DIFFERENT request class
  providers may limit independently. Pin shape parity with a test that asserts the full
  filter, not the one field that motivated the claim. (PR #129 round 3, finding 4.)
- Caller-controlled map KEYS are the same log-injection/credential surface as values:
  CR/LF keys forge log lines, huge keys flood, URL-shaped keys carry secrets. Identify
  invalid entries by ordinal and valid ones by their canonical catalogue name; never echo
  the raw key. "It's just a dictionary key" is not a sanitization exemption. (PR #129
  round 3, finding 2.)
- An issue's acceptance criterion is the ISSUE OWNER's to amend: implement the honest
  subset, make the gap STRUCTURAL (a documented exclusion set + a partition invariant
  test that fails when an entry is silently in neither set), and propose the narrowing on
  the issue itself for sign-off with a follow-up issue — do not declare it narrowed in
  the PRD/README from the PR side. (PR #129 round 3, finding 3.)
- Resolver-side skew tolerance is leniency for READING, never permission to WRITE future
  time. did:webvh's Update algorithm requires the entry timestamp to be "the time the DID
  will be retrieved by a witness or resolver, or before" — so a writer needing whole-second
  identity must WAIT (bounded) for the next whole second to actually arrive, or fail
  honestly; it must not manufacture time ahead of the clock and justify it with the
  resolver's read-side tolerance. Corollary: a SHOULD-maximum ("no more than 5 minutes")
  is a ceiling on others' leniency, not a floor you may consume — a conforming resolver
  with a 30-second tolerance breaks every "margin under every conforming resolver" claim.
  (PR #132 review round 1, findings 1+3.)
- An operation that cannot take effect under the spec's invariants must fail with an honest
  retry contract, not return Success. Exempting Deactivate from the future-skew bound
  "fixed" a denial-of-revocation by emitting an entry conforming resolvers reject — false
  assurance, worse than the failure. When strict monotonicity + no-future-authoring make
  immediate append past a future head impossible, the truthful contract is: throw, tell the
  caller when retrying can work, and document the impossibility. (PR #132 round 1, finding 2.)
- Pin a changed numeric security constant with a case BETWEEN the old and new values; a
  rejection test beyond both (e.g. +6min against both a 5-min and 1-min budget) is green
  under a revert and pins nothing. And when the invariant is "authored X never exceeds
  observation time", assert exactly that against an injected deterministic clock — my
  adversarial agents and tests validated NetDid against NetDid's own resolver (which lacks
  the read-side MUST, #131), so a spec-violating writer passed its own suite. The oracle
  for a writer-conformance property is the spec's writer rule, not the library's reader.
  (PR #132 round 1, finding 4.)
- A per-delay timeout is not an aggregate deadline when UTC can stall or move backward: capture
  one monotonic start timestamp and spend one remaining budget across every retry. After any
  awaited timer, check monotonic elapsed BEFORE returning an otherwise eligible result — process
  suspension or thread starvation can make UTC reach the target only after the deadline. Define
  the boundary explicitly: eligible at exactly the limit may succeed; over-limit success and
  non-eligible-at-limit both fail. Tests must separate UTC from monotonic time and pin frozen,
  backward, cancellation, exact-boundary, and overslept-timer shapes. (PR #132 round 2.)
- A REBASE is a mechanical task, not a change to be re-proven from scratch. When a branch that
  already passed the full gate is rebased onto main, scale verification to what the merge could
  actually break: resolve the conflicts, build, run the AFFECTED test project(s), and regenerate
  any generated file both sides touched. Do not re-run the entire net-did-verify gate (full
  Release suite + all five samples + full vector replay) unless a conflict landed in shared
  runtime code. The user pinged "this was a simple request to fix a merge conflict and it's
  taking too damn long" — the third instance of the proportionality failure (issues #101, #112).
  Ceremony is justified by what the diff can break, and a conflict resolution in docs plus one
  generated report can break almost nothing.
- When a witness/controller proof is a W3C Data Integrity proof, DELEGATE verification to the
  DataIntegrityProofPipeline over the proof's COMPLETE wire configuration (capture RawJson at
  parse, re-emit verbatim on republish) — never hand-reconstruct a reduced proof from modeled
  fields. A reduced reconstruction (type/cryptosuite/vm/created/purpose/value only) silently
  drops signature-bound members (`id`/`expires`/`nonce`/extensions): a conforming proof with
  `expires` is rejected, republish corrupts it, and — the real hole — an attacker appends an
  UNSIGNED member and the truncated original still verifies. The pipeline strips the whole
  `proof` member before hashing the document, so verifying one proof in an isolated
  `{"versionId":X,"proof":[<that proof>]}` secured doc is correct (reduces to bare
  `{"versionId":X}`); other proofs for the same version need not be present. This mirrors the
  #101 controller-proof lesson — the witness path had drifted from it. (PR #143 review round 2, F1.)
- A witness/threshold verifier over untrusted input needs a CPU bound, not just a byte-cap:
  `created` is signer-chosen so one key mints unlimited distinct valid proofs, and a <=1 MiB
  file holds thousands. Bound it with ONE shared per-run session: index the file once, memoize
  each proof's verdict (reference-keyed — the index owns the canonical instance) across every
  governed entry so cumulative coverage reuses verdicts instead of re-verifying O(entries×proofs),
  pre-filter unconfigured/duplicate/wrong-purpose/wrong-VM-form signers BEFORE any cryptography,
  stop per-entry scanning at the threshold, honor cancellation, and enforce a configurable
  verification budget that fails closed. Memo soundness precondition: each proof instance is filed
  under exactly ONE chain-validated versionId, so its single verdict is for exactly one secured
  document. (PR #143 review round 2, F5.)
- "Consume whenever supplied" beats "consume only alongside a new batch": a parse-and-throw guard
  nested under `if (newProofs.Count > 0)` lets garbage/legacy `CurrentWitnessContent` pass silently
  when the caller sends no new proofs — the exact silent-ignore class the fix claimed to close.
  Hoist supplied-input validation above the batch check. And a merge that REPLACES a version's
  aggregate breaks incremental collection (republish-as-approvals-arrive): APPEND + dedupe
  byte-identical, or a second publish sinks an already-satisfied threshold. (PR #143 review round 2,
  F2+F4.)
