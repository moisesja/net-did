# Lessons

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
