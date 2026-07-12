---
name: net-did-fix
description: End-to-end playbook for resolving a GitHub issue or bug in the net-did .NET library — assess-with-citations, branch, fail-first regression tests, verify, adversarial review, docs+CHANGELOG, PR. Use when asked to fix, implement, or close a net-did issue (e.g. "fix #NN", "implement issue NN", "resolve this bug"). Makes CLAUDE.md's Task Management + Autonomous Bug Fixing principles executable.
---

# net-did issue-fix cycle

The repeatable loop this repo runs for every issue/bug fix. Follow the steps in order; each maps to a section you append to the plan file. Do the minimal correct change — CLAUDE.md's "Simplicity First / Minimal Impact / No Laziness."

## 0. Prerequisites
- Read the issue (`gh issue view NN`) and `tasks/lessons.md` before touching code.
- Confirm the working tree is clean and you know the base branch (usually `main`). If dirty or the checkout changed since planning, re-baseline first (lessons: don't carry stale worktree assumptions).

## 1. Assess with citations
- Validate the report against **actual source**, citing `path/File.cs:line` for the root cause. Don't trust the issue's framing — confirm it.
- Explicitly enumerate **out-of-scope** code paths and justify each exclusion (recurring rationale style: "CPU-bound, never observes `ct`, a guard would be dead code").
- Assign severity (High/Medium/Low) matching the issue.
- For anything spec-governed, verify the intended behavior against the **normative spec text** before coding — see `spec-conformance-audit` and the lessons about writer/reader parity not being conformance.

## 2. Branch + plan file
- Branch off the base: `fix/issue-NN-slug` (or `feat/issue-NN-slug`). For breaking/significant work, create the branch **immediately after plan approval, before the first edit** (lessons).
- Copy the plan into `tasks/todo{timestamp}.md` (`# Title` → `## Context` → `## Plan` `[ ]` checklist → `## Files touched` table → `## Review`).
- Non-trivial (≥3 steps or architectural) ⇒ get plan approval via EnterPlanMode/ExitPlanMode BEFORE editing source. Writing the plan file is **not** approval (lessons).

## 3. Implement minimally
- Smallest change that fixes the root cause at one enforcement point. No temporary fixes.
- Snapshot caller-supplied interface-typed collections **once** at trust boundaries (see `adversarial-review`).

## 4. Regression tests — fail-first
- Name them `IssueNN_*`, grouped in a region alongside prior `IssueNN_*` blocks.
- Cover the **full affected surface**, not just the first case (e.g. every EC curve, every media type) — partial coverage is why issues get reopened.
- **Prove the test fails against the pre-fix code**: stash the fix, run the test, confirm it FAILS, restore. Record this in the Review.
- Stack: xUnit + NSubstitute + FluentAssertions. Method-specific hostile-input tests go in `NetDid.Method.*.Tests`; DID-Core statements go in `NetDid.Tests.W3CConformance`.

## 5. Verify
Run the **`net-did-verify`** skill (0-warning Release build, full test suite with per-project counts, W3C conformance green, samples end-to-end, clean `git diff --check`). Never mark done without proving it works.

## 6. Adversarial review
Run the **`adversarial-review`** skill on the completed diff (mandatory per CLAUDE.md §2). Fix anything CONFIRMED, then re-verify the affected paths.

## 7. Docs + CHANGELOG
- Update `NetDidPRD.md` (source of truth) and `README.md` if public behavior changed.
- Add a `CHANGELOG.md` entry under `[Unreleased]` (`Added`/`Changed`/`Fixed`/`Security`).
- **Do NOT bump `NetDidVersion`** — version bumps happen only in the release PR (memory: `feedback_version-bumps`). Releasing is the separate `net-did-release` skill.

## 8. PR + review section
- Commit, push, open a PR with `Fixes #NN` in the body.
- **Stop at the open PR.** Do not merge — the user reviews and merges, even under "take it as far as possible" (lessons + memory `feedback_pr-merge-review`). Merge only on an explicit per-PR "merge it".
- Append a `## Review` section to the plan file: files changed, exact test counts, acceptance-criteria re-check, fail-first evidence, behavior diff vs. `main`, PR URL.
- After a maintainer review round, address findings and record them (see `todo20260711-issue91.md` for the format).

## Guardrails (from lessons.md)
- A user constraint like "stay on this branch" is a scope guardrail, **not** approval to skip plan review.
- When the user narrows scope mid-thread, restate the corrected scope and revalidate only that before acting on the tracker.
- Security restrictions that remove a previously working path are **breaking changes** even when secure-by-default — document the affected paths and the supported replacement.
