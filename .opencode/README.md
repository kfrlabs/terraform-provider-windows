# .opencode/

Project-local OpenCode V2 customizations for this repository. OpenCode is the only agent harness configured here.

- `agents/` — Markdown agent definitions, discovered as `.opencode/agents/<name>.md`.
  A nested path becomes part of the agent id (e.g. `.opencode/agents/acc/lab-runner.md` -> `acc/lab-runner`).
- `commands/` — Markdown slash-command templates, discovered as `.opencode/commands/<name>.md`.
  A nested path becomes a namespaced command (e.g. `.opencode/commands/terraform/acc-resource.md` -> `/terraform/acc-resource`).
- `docs/` — shared reference material read by agents (not discovered by OpenCode).
- `chains/` — traceability manifests written by `win-spec-analyst` for `/windows-resource` runs (created on demand).

Reference: https://opencode.ai/v2/docs/agents and https://opencode.ai/v2/docs/commands

## `/windows-resource` — generate a resource or data source

Orchestrator: `commands/windows-resource.md`. It owns git and drives five subagents
(`mode: subagent`): `win-spec-analyst` → `schema-architect` → `provider-coder` →
`test-engineer` → `quality-gate`, with a fix-loop capped at 3 attempts.

## `/terraform/acc-resource` — acceptance campaign on one resource

Orchestrator: `commands/terraform/acc-resource.md`. It runs a real Terraform CLI
campaign from LAB 201 against LAB 203 for exactly one resource, plus its twin data
source when it exists. Lab facts (hosts, build, run layout, safety rules) live in
`docs/acc-lab.md`.

| Step | Agent |
|---|---|
| Lab checks, cross-compile, upload, smoke | `acc/lab-preflight` |
| Scenario matrix and HCL | `acc/scenario-designer` |
| Real runs, verification on 203, cleanup | `acc/lab-runner` |
| Triage, minimal repro, root cause, regression scenario, final report | `acc/bug-analyst` |
| Fix (`FEEDBACK_SOURCE=acceptance`) | `provider-coder` |
| Diff review | `reviewer` (global) |

Run artifacts stay in `work/acc/<r>/<run_id>/` (gitignored); regression scenarios are
versioned under `test/acc/<r>/`.

Subagents never touch git. Orchestrators decide branches, commits and PRs but delegate
them to the global agents: `git-inspector` (read-only checks), `git-operator` (branch,
commit, push) and `pr-manager` (PR creation), passing the user's authorization explicitly.
