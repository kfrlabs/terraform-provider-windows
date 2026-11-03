# ADR-0009 — Data source support in the resource pipeline

- Status: Accepted
- Date: 2026-05-08
- Supersedes: none
- Relates to: ADR-0008 (decoupled chain)

## Context

The pipeline `win-spec-analyst → schema-architect → provider-coder → test-engineer → quality-gate` was designed exclusively for **managed resources** (full CRUD + Import). We now need to ship Terraform **data sources** (read-only, no state mutation), starting with `windows_winget_package`, `windows_legacy_package` and likely a generic `windows_installed_packages` inventory.

Resources and data sources share ~80% of the build infrastructure (CHAIN_BRANCH, manifest, lint, audit, fix-loop, doc generation). Forking the pipeline into two parallel sets of tasks would duplicate prompts and guarantee maintenance drift.

## Decision

Introduce a single optional input parameter `KIND ∈ {resource, datasource}` (default `resource`) propagated through every worker in the chain. Each worker branches its behaviour locally on `KIND` while keeping a single prompt.

## Consequences

### Inputs schema

Every task in the chain accepts `KIND` as an optional string with `enum: [resource, datasource]` and default `resource`. The launcher (`windows-resource`) is the only entry point where the human/caller sets `KIND`; downstream workers receive it through the `input` string forwarded by their predecessor.

### CHAIN_BRANCH naming

To avoid collisions when a resource and a data source share the same Terraform name (e.g. `windows_winget_package`), the launcher MUST suffix `-ds` when `KIND=datasource`:

```
resource   → kdust/chain/<RESOURCE>-<YYMMDDHHMM_UTC>
datasource → kdust/chain/<RESOURCE>-ds-<YYMMDDHHMM_UTC>
```

The pattern in `win-spec-analyst.inputs_schema.CHAIN_BRANCH` (`^kdust/chain/.+-[0-9]{10}$`) already accepts the `-ds-` infix.

### Terraform naming convention (CRITICAL)

A Terraform data source uses the **same type name** as its sibling resource. Both `resource "windows_winget_package"` and `data "windows_winget_package"` coexist; Terraform disambiguates via the block keyword (`resource` vs `data`), not via the name. Workers MUST NOT suffix the artefact name (`_data`, `_info`, `_lookup`, etc.).

### File-naming conventions (matching existing repo layout)

Let `<r>` = the suffix without the `windows_` prefix and `<R>` = its PascalCase form.

| Layer | Resource | Data source |
|---|---|---|
| Provider Go file | `internal/provider/resource_windows_<r>.go` | `internal/provider/datasource_windows_<r>.go` |
| Constructor | `NewWindows<R>Resource()` | `NewWindows<R>DataSource()` |
| Internal type | `windows<R>Resource` | `windows<R>DataSource` |
| winclient impl | `internal/winclient/<r>.go` (interface inline + impl + assertion) | **NO new file** — reuses sibling resource client's `Read` |
| winclient types | `internal/winclient/<r>_types.go` (optional) | reuses sibling resource types |
| Provider registration | `Resources()` in `provider.go` | `DataSources()` in `provider.go` |
| Unit tests provider | `resource_windows_<r>_test.go` | `datasource_windows_<r>_test.go` |
| Acceptance tests provider | `resource_windows_<r>_acc_test.go` | `datasource_windows_<r>_acc_test.go` |
| Unit tests winclient | `<r>_client_impl_test.go` | enriches the resource's `<r>_client_impl_test.go` if `Read` not_found case is missing |
| Docs | `docs/resources/<r>.md` (no `windows_` prefix) | `docs/data-sources/<r>.md` (no `windows_` prefix) |
| Examples | `examples/resources/windows_<r>/resource.tf` + `import.sh` | `examples/data-sources/windows_<r>/data-source.tf` (no `import.sh`) |
| CHANGELOG section | `### Resources` | `### Data Sources` |

### Per-worker behaviour (datasource mode)

| Worker | resource | datasource |
|---|---|---|
| `win-spec-analyst` | full CRUD spec | spec with `kind: datasource`, `operations.read` only, no `force_new`, no `import`, all non-key attrs `computed: true`, plus `reuses_resource_client: true` if sibling resource exists |
| `schema-architect` | `resource_windows_<r>.go` + winclient `<r>.go` skeleton + register in `Resources()` | `datasource_windows_<r>.go` + register in `DataSources()`. **No new winclient file** (reuses sibling resource's `<R>Client`). No `PlanModifier`, no `Default`. |
| `provider-coder` | implement Create/Read/Update/Delete/ImportState + winclient impl | implement provider `Read` only, calling sibling resource client's `Read`. **No winclient touch.** ESCALATE if sibling client lacks needed method. |
| `test-engineer` | unit (`_test.go`) + acceptance (`_acc_test.go`) covering full CRUD/Update/Drift/Import/CheckDestroy | unit `_test.go` (Read mapping + not_found + error cases) + acceptance `_acc_test.go` (`_basic` + `_notFound`). No Update/Drift/Import/CheckDestroy. |
| `quality-gate` | `docs/resources/<r>.md`, `examples/resources/windows_<r>/{resource.tf,import.sh}`, CHANGELOG `### Resources` | `docs/data-sources/<r>.md`, `examples/data-sources/windows_<r>/data-source.tf` (no `import.sh`), CHANGELOG `### Data Sources`. Verifies no winclient additions. |

### Provider registration

`internal/provider/provider.go` already implements both `Resources()` and `DataSources()`. `schema-architect` adds the new entry to whichever slice matches `KIND`, preserving alphabetical order.

### Spec manifest

The `.kdust/chains/<RESOURCE>[-ds]-<ts>.yaml` manifest grows a top-level `kind: <resource|datasource>` field (default `resource` for backward compat with existing manifests). Diff-detection logic is unchanged.

### Failure modes & escalation

Unchanged. ATTEMPT counters, fix-loop boundaries (max 3), ESCALATE on schema/spec defects all behave identically across both kinds.

## Migration

1. Patch the 6 task prompts (canonical sources tracked under `.kdust/prompts/v2/`).
2. Patch `inputs_schema` of all 6 tasks to declare `KIND` (already done via `task_runner__update_task_routing`).
3. Run end-to-end on `windows_winget_package` data source as the first cobaye.
4. Backport learnings into the prompts before tackling `windows_legacy_package`.

## Alternatives considered

- **Parallel `*-ds` task set**: rejected — 80% prompt duplication, drift guaranteed.
- **Detect `KIND` from spec.yaml only (no input plumbing)**: rejected — `schema-architect` needs `KIND` before reading the spec on disk to decide which template to invoke; cleaner to make it a first-class input.
- **Separate winclient `<R>DataSourceClient` interface and types**: rejected — the existing pattern (single `<R>Client` with `Read` reused by the data source) is simpler, avoids duplication, and matches all existing data sources in the repo (see `windows_environment_variable`).
