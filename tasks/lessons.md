# Lessons

- When the user corrects or narrows a request mid-thread, restate the corrected scope explicitly in the next work pass and revalidate only that scope before taking issue-tracker actions.
- CLAUDE.md "Plan First" / "Verify Plan" means: for any non-trivial task (≥3 steps or architectural decisions), write the plan to `tasks/todo{timestamp}.md` AND present it to the user for approval BEFORE editing any source files. Writing the plan file is not the same as getting approval — use `EnterPlanMode` / `ExitPlanMode` (or an explicit "OK to proceed?" check) and wait for a yes. A user constraint like "stay on this branch" is a scope guardrail, not approval to skip the plan-review step.
