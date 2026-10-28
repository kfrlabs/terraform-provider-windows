# .claude/

Claude Code port of this repository's KDust resource-generation pipeline
(see `CLAUDE.md`).

- `agents/` — subagent definitions invoked by the `/windows-resource`
  orchestrator via the Task tool (`win-spec-analyst`, `schema-architect`,
  `provider-coder`, `test-engineer`, `quality-gate`).
- `commands/` — the `/windows-resource` orchestrator slash command.

## Canonical prompts and sync

The functional source of truth is `.kdust/prompts/v2/`. Both this directory
and `.opencode/agents/` + `.opencode/commands/windows-resource.md` are
derived ports of it: every `agents/*.md` file here is byte-identical to its
`.opencode/` counterpart (verify with
`cmp .claude/agents/<name>.md .opencode/agents/<name>.md`), and the
orchestrator command matches `.opencode/commands/windows-resource.md`. The
ports adapt the pipeline model (the orchestrator owns git and the fix loop;
subagents never commit) while `.kdust/prompts/v2/` keeps the original
pipeline semantics — expect wording drift there by design.

When the pipeline changes:

1. Edit `.kdust/prompts/v2/` first.
2. Port the change to both `.claude/` and `.opencode/` copies so they stay
   byte-identical.
3. Re-verify with `cmp` before committing.

`.kdust/chains/` holds historical pipeline run records, not live
configuration; leave completed runs untouched.
