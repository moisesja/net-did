# Adopt fork PR #70 (did:ethr) — NetCrypto-only crypto, parked until upstream ships

Plan reference: `/Users/moises/.claude/plans/wobbly-knitting-stonebraker.md`
User decisions: (1) adopt via merge (preserve @mirceanis credit); (2) crypto exclusively from NetCrypto, upstream requests for gaps; (3) "Issue only, pause net-did" sequencing.

## Phase 0 — Upstream request
- [ ] Confirm crypto-dotnet repo slug (`moisesja/crypto-dotnet`) ✔ issues enabled
- [ ] Draft issue: public secp256k1 compressed→uncompressed decompression; user approves wording
- [ ] File issue, capture URL for TODO annotation

## Phase 1 — Branch + merge + mechanical adaptation (single merge commit)
- [ ] `git checkout -b feat/did-ethr-resolver pr-70 && git merge main`
- [ ] Resolve 7 conflicts per plan (.gitignore, Directory.Packages.props [NO acryptohashnet pin], NetDidBuilder.cs, TestDidFactory.cs, CHANGELOG.md, README.md, w3c-conformance-report.md)
- [ ] Namespace redirects: `NetDid.Core.Crypto`/`.Jwk`/`ISigner`/`IKeyGenerator` → `NetCrypto` (~8 files)
- [ ] Keccak migration: 4 sites + test KATs → static `NetCrypto.Keccak256.Hash`; remove acryptohashnet pkg ref; `git grep -i acryptohashnet` = 0 hits
- [ ] Annotate `EthereumAddress.cs` decompression site: `// TODO(<issue url>)` — only remaining non-NetCrypto crypto call
- [ ] Commit merge

## Phase 2 — Park branch green
- [ ] `dotnet build -c Release` → 0 warnings (watch: NBitcoin 4.0.0 `ECPubKey.TryCreate` shape; NetCid 1.6.0 `Multibase.Encode`)
- [ ] Full test suite green (watch-points: `ComputeContext` security/v2 skip; `VerificationMethodJsonConverter` AdditionalProperties flush must not regress did:key/peer/webvh)
- [ ] Regenerate `w3c-conformance-report.md`; fix README per-project test counts
- [ ] Push `feat/did-ethr-resolver` to origin — **do NOT open PR**
- [ ] Review section below + memory note with pause state

## Paused — resume when NetCrypto ships public decompress API
1. Bump NetCrypto pin in `Directory.Packages.props`
2. Swap `EthereumAddress.cs` to new API; remove `using NBitcoin.Secp256k1;`; `git grep NBitcoin` in ethr = 0
3. `net-did-verify` full gate
4. `adversarial-review` (untrusted RPC decoding; worktree isolation)
5. Open PR crediting @mirceanis / linking #70 — stop; Moises merges

## Review

_(to be filled at pause point)_
