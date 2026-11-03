# Architecture Decision Records

Accepted design decisions for terraform-provider-windows. New records go
here as `ADR-NNNN-short-title.md`, numbered sequentially.

Numbering note: ADR-0001 through ADR-0008 predate this repository and are
absent; the in-repo sequence starts at ADR-0009. References to ADR-0008 in
`.kdust/prompts/v2/` and in ADR-0009 ("decoupled chain") are historical.

Index:

- [ADR-0009](ADR-0009-datasource-pipeline-support.md) — resource-vs-data-source naming and file conventions.
- [ADR-0010](ADR-0010-ssh-transport.md) — SSH transport (persistent PowerShell session, stdin secrets).
- [ADR-0011](ADR-0011-host-key-verification.md) — host key verification (fail-closed, known-hosts).

These records live outside `docs/` on purpose: `docs/` is generated from
schemas + examples by `make docs` and guarded by the blocking drift gate,
so hand-maintained design docs do not belong there.
