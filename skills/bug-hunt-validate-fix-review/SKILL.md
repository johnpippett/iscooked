---
name: bug-hunt-validate-fix-review
description: Use when hunting possible code bugs and the user wants suspected issues independently validated before fixes.
---

# Bug Hunt, Validate, Fix, Review

## Workflow

1. Read project rules first: `AGENTS.md`, relevant `skills/`, and `wiki/`.
2. Hunt for concrete bug candidates with evidence: failing tests, static warnings, suspicious control flow, stale docs, or minimal repros.
3. Notate each candidate where it will survive: a regression test name/comment, review note, or JD wiki note.
4. Dispatch one independent subagent per candidate. Each subagent must make no edits and return:
   - `EXISTS` or `NOT FOUND`
   - exact evidence
   - affected file/line
   - smallest conventional fix
5. Implement only confirmed bugs. Prefer the smallest common fix that preserves existing style.
6. Add or update focused regression tests before or alongside the fix. Keep tests named after the bug behavior.
7. Run the closest verification command. If the normal runner is missing, use a documented local fallback and say so.
8. Dispatch a final review subagent over the whole diff. Fix any critical or important issues before final.
9. Update the JD wiki for meaningful code, config, workflow, or debugging changes.

## Guardrails

- Do not fix unvalidated guesses.
- Do not let one subagent edit files while another investigates the same area.
- Keep implementation scope narrower than the bug list.
- Preserve unrelated dirty worktree changes.
- Do not commit, push, deploy, or rewrite history unless explicitly asked.

## Final Report

Report confirmed bugs, files changed, verification results, reviewer outcome, and wiki file updated.
