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

## Canonical prompts and sync

`.kdust/prompts/v2/` is canonical. `.claude/agents/` and `.opencode/agents/`
are derived ports: every `agents/*.md` file is byte-identical across the two
directories (verify with
`cmp .claude/agents/<name>.md .opencode/agents/<name>.md`), as is the
`/windows-resource` orchestrator (`.claude/commands/windows-resource.md`
versus `.opencode/commands/windows-resource.md`). The ports adapt the
pipeline model (the orchestrator owns git and the fix loop; subagents never
commit) while `.kdust/prompts/v2/` keeps the original pipeline semantics —
expect wording drift there by design.

When the pipeline changes:

1. Edit `.kdust/prompts/v2/` first.
2. Port the change to both the `.claude/` and `.opencode/` copies so they
   stay byte-identical.
3. Re-verify with `cmp` before committing.

`.kdust/chains/` holds historical pipeline run records, not live
configuration; leave completed runs untouched.
