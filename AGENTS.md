# Agent & Contributor Instructions

This file provides instructions for AI agents and human contributors working in this codebase.

## Project Overview

NetDid is an open-source .NET 10 library that provides a unified, specification-compliant interface for creating, resolving, updating, and deactivating Decentralized Identifiers. Currently implemented: `did:key` and `did:peer`. Planned: `did:webvh` and `did:ethr`.

## Requirements and Design

See [`NetDidPRD.md`](NetDidPRD.md) for requirements and architecture of the system. This document must be maintained as it will be the main source of truth for functionality details.

## Workflow Skills

This repo ships project skills in `.claude/skills/` that operationalize the principles in this file — they encode the exact commands, conventions, and hard-won `tasks/lessons.md` rules for this codebase. **Prefer invoking the skill over improvising the workflow.** The sections below state the *why*; these skills are the *how*.

| Skill | Invoke when | Encodes |
|---|---|---|
| `net-did-fix` | fixing, implementing, or closing an issue/bug | full issue-fix cycle: assess-with-citations → branch → fail-first `IssueNN_*` tests → verify → adversarial → docs+CHANGELOG → PR (stop before merge) |
| `net-did-verify` | before marking any change done or opening a PR | the "done" gate: 0-warning Release build, per-project test counts, W3C conformance green, samples end-to-end |
| `net-did-release` | cutting a version / publishing to NuGet | semver → release branch → `NetDidVersion` bump → CHANGELOG stamp → tag `vX.Y.Z` → publish.yml → confirm on NuGet |
| `adversarial-review` | after any security-sensitive change, before the PR | the mandated red-team pass encoding the `tasks/lessons.md` security rules |
| `spec-conformance-audit` | auditing the code against the DID specs | audit → one GitHub issue per finding with normative-spec cross-check |

`net-did-fix` is the orchestrator for issue/bug work and calls `net-did-verify` and `adversarial-review` at the right steps.

## Workflow Orchestration

### 1. Plan Mode Fault

- Enter plan mode for ANY non-trivial task defined as a task that takes 3 steps or more or that requires architectural decisions.
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy

- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution
- Always use adversarial agents to attempt to exploit the code that is being generated. The adversarial agents must report in detail about any findings → run the **`adversarial-review`** skill, which drives this pass and carries the accumulated `tasks/lessons.md` rules

### 3. Self-Improvement Loop

- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done

- Run the **`net-did-verify`** skill — it is the concrete "done" gate for this repo
- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this,"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)

- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing

- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

# Task Management

For issue/bug work, the **`net-did-fix`** skill runs this whole sequence end-to-end; **`net-did-release`** covers step 7 when shipping a version. The steps below remain the canonical description of what those skills do.

1. **Plan First**: Write plan to `tasks/todo{timestamp}.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section`to 'tasks/todo{timestamp}.md`
6. **Capture Lessons**: Update 'tasks/lessons.md' after corrections
7. **Update CHANGELOG.md**: After the successful validation of a task, update the CHANGELOG.md with sufficient details

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Staff Engineer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
