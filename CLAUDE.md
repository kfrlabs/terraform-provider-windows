# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

A Terraform provider that manages Windows resources over WinRM by executing PowerShell on the target host. Built on the **Terraform Plugin Framework** (TPF, `terraform-plugin-framework`) — not the legacy SDKv2.

## Commands

All common tasks go through the `GNUmakefile` (`Makefile` is an identical copy):

| Command | Purpose |
| --- | --- |
| `make build` | `go install ./...` |
| `make test` | Short unit tests: `go test -short ./... -timeout 30s` |
| `make testacc` | Acceptance tests: `TF_ACC=1 go test -tags acceptance ./... -v -timeout 120m` |
| `make lint` | `golangci-lint run` |
| `make fmt` | `gofmt -s -w .` + `terraform fmt -recursive examples/` |
| `make docs` | Regenerate `docs/` via `tfplugindocs` (`go generate ./...`) |

Run a single test:
```bash
go test ./internal/provider/ -run TestWindowsFeatureResource -v
go test ./internal/winclient/ -run TestFeatureClient -v
```

Acceptance tests require `TF_ACC=1` plus `WINDOWS_HOST`, `WINDOWS_USERNAME`, `WINDOWS_PASSWORD` and a reachable Windows target; without them they skip. They also live behind the `acceptance` build tag (`-tags acceptance`) and share `testAccProtoV6ProviderFactories` from `internal/provider/acc_test_helper.go`; the default `make test` build never compiles them. The `testacc-windows` workflow (`.github/workflows/testacc-windows.yml`, `workflow_dispatch`) runs them on a GitHub-hosted `windows-latest` runner that targets its own local WinRM. Unit tests never touch WinRM.

Enabled linters (`.golangci.yml`): `errcheck`, `gofmt` (simplify), `gosec`, `govet`, `ineffassign`, `staticcheck`, `unused`. `_test.go` files are excluded from `errcheck`/`gosec`.

## Architecture

Three layers, top to bottom:

1. **`internal/provider/`** — TPF layer. Provider config + schemas, models, CRUD/ImportState handlers, diagnostics. No WinRM or PowerShell here.
2. **`internal/winclient/`** — WinRM/PowerShell layer. Builds and runs PowerShell, parses results, returns Go structs and structured errors.
3. **Remote Windows host** — reached via `masterzen/winrm`.

### Provider wiring (`internal/provider/provider.go`)
`Configure` reads provider config, applies `WINDOWS_*` env fallbacks (`winclient.ResolveFromEnv`), builds one shared `*winclient.Client`, and hands it to every resource/data source via `resp.ResourceData` / `resp.DataSourceData`. Each resource/data source's `Configure` type-asserts `req.ProviderData.(*winclient.Client)` and wraps it in its specific client (e.g. `winclient.NewFeatureClient(c)`). New resources/data sources must be registered in the `Resources()` / `DataSources()` slices.

### winclient layer
`client.go` is the WinRM wrapper. The key primitive is `RunPowerShell(ctx, script)`. Only a fixed bootstrap rides on the command line via `powershell.exe -EncodedCommand`; the real script (UTF-16LE base64) is streamed on **stdin** and decoded by the bootstrap, so the command line stays a constant ~600 chars and never hits Windows' ~8191-char limit regardless of script size. `RunPowerShellWithInput` appends secrets after the script on stdin so plaintext never appears in the encoded command or WinRM trace logs — use it for passwords and other sensitive values; the script reads them via `[Console]::In.ReadLine()` / `ReadToEnd()`.

Conventions every winclient resource follows:
- PowerShell scripts wrap output in a **JSON envelope** via `Emit-OK` / `Emit-Err` helpers, so stdout is machine-parseable regardless of Windows locale. Always set `$ErrorActionPreference='Stop'` and silence progress/warning streams.
- User-supplied values are interpolated **only** through `psQuote` (single-quoted PowerShell literal) to prevent `$var` / backtick / subexpression injection. Never string-concat raw input into a script.
- A per-resource `Classify-*` PowerShell function maps localized error substrings to a `<Resource>ErrorKind`. Each resource defines a structured `<Resource>Error` (Kind/Message/Context/Cause) implementing `Error`/`Unwrap`/`Is` (matches on `Kind`), so the provider layer branches with `errors.As` / `errors.Is`.

### Per-resource file layout
For a Terraform name `windows_<r>` with PascalCase `<R>`:

| Layer | File |
| --- | --- |
| TPF resource | `internal/provider/resource_windows_<r>.go` (`NewWindows<R>Resource`, `windows<R>Resource`) |
| TPF data source | `internal/provider/datasource_windows_<r>.go` (`NewWindows<R>DataSource`) |
| winclient impl | `internal/winclient/<r>.go` (concrete client + `var _ Interface = (*Impl)(nil)` assertion) |
| winclient types | `internal/winclient/<r>_types.go` (interface, info/result structs, error kinds) |
| Unit tests | `*_test.go` (provider: fakes injected into the client field; winclient: `<r>_client_impl_test.go`) |
| Acceptance tests | `*_acc_test.go` |
| Docs | `docs/resources/<r>.md`, `docs/data-sources/<r>.md` (no `windows_` prefix) |
| Examples | `examples/resources/windows_<r>/{resource.tf,import.sh}`, `examples/data-sources/windows_<r>/data-source.tf` |

The provider layer depends on a winclient **interface** (e.g. `WindowsFeatureClient`), not the concrete type, which is what lets unit tests inject a fake client and exercise CRUD without WinRM.

### Data sources
A data source shares the **same** Terraform type name as its sibling resource (Terraform disambiguates by `resource` vs `data` block). Never suffix names with `_data`/`_info`. Data sources reuse the sibling resource's winclient `Read` — no new winclient file.

## Code generation context

This provider is generated by a multi-agent "KDust" pipeline; most files carry a "Generated by KDust" header. Pipeline prompts live in `.kdust/prompts/v2/` and design decisions in `docs/adr/` (notably **ADR-0009** for resource-vs-data-source naming/file conventions). When adding a resource by hand, mirror an existing one end-to-end (e.g. `feature`) so it stays consistent with what the pipeline emits. `docs/` is generated from schemas + `examples/` + `templates/` — run `make docs` and commit the result; CI is expected to fail if `docs/` drifts.

### Generating a resource via `/windows-resource`
The Claude Code port of the KDust pipeline lives in `.claude/`. The `/windows-resource` slash command (`.claude/commands/windows-resource.md`) is the orchestrator: it owns git (branch, per-phase commits, PR) and drives five subagents in `.claude/agents/` via the Task tool — `win-spec-analyst` → `schema-architect` → `provider-coder` → `test-engineer` → `quality-gate`, with a `provider-coder ⇄ test-engineer/quality-gate` fix-loop capped at 3 attempts. On a clean pass it pushes the `kdust/chain/<resource>[-ds]-<ts>` branch and opens a PR against `main`. Invoke: `/windows-resource RESOURCE=windows_<name> DESCRIPTION="..." [KIND=resource|datasource]`. Subagents only write files and a status block; never let them touch git. The `.kdust/prompts/v2/` prompts remain the functional source of truth these agents are derived from.

## Notes

- `kerberos` `auth_type` is declared but **not implemented** (`ntlm` default, `basic` supported).
- Resources with slow operations set a generous default timeout and expose a `timeouts {}` block (`terraform-plugin-framework-timeouts`); e.g. `windows_feature` defaults to 30m because Server roles can take 10+ minutes.
