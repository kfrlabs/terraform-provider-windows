# .opencode/

Project-local OpenCode V2 customizations for this repository.

- `agents/` — Markdown agent definitions, discovered as `.opencode/agents/<name>.md`.
  A nested path becomes part of the agent id (e.g. `.opencode/agents/team/reviewer.md` -> `team/reviewer`).
- `commands/` — Markdown slash-command templates, discovered as `.opencode/commands/<name>.md`.
  A nested path becomes a namespaced command (e.g. `.opencode/commands/team/review.md` -> `/team/review`).

Reference: https://opencode.ai/v2/docs/agents and https://opencode.ai/v2/docs/commands

## Porting from the Claude Code pipeline

This repo already ships a Claude Code port of the KDust resource-generation
pipeline under `.claude/agents/` and `.claude/commands/windows-resource.md`
(see `CLAUDE.md`). When porting a subagent or the `/windows-resource`
orchestrator to OpenCode:

- Move the system prompt into the Markdown body of an `.opencode/agents/<name>.md` file.
- Set `mode: subagent` for agents that should only run as child sessions
  (mirrors the Task-tool subagents: `win-spec-analyst`, `schema-architect`,
  `provider-coder`, `test-engineer`, `quality-gate`).
- Recreate `/windows-resource` as `.opencode/commands/windows-resource.md`,
  using `$ARGUMENTS` (or `$1`/`$2`) for `RESOURCE=`, `DESCRIPTION=`, `KIND=`.
- Keep `.kdust/prompts/v2/` as the functional source of truth; both the
  `.claude/` and `.opencode/` ports should stay derived from it.
