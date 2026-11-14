# ADR-0013 — Shared winclient envelope prelude, generic error and input conventions

- Status: Accepted
- Date: 2026-11-14
- Supersedes: none
- Relates to: issue #348; issue #178 (Go-side run/envelope consolidation); issue #173, #203 (quoting fixes); #81 (persistent session safety)

## Context

Issue #178 consolidated the Go-side run/envelope path (`runEnvelope` in
`internal/winclient/envelope.go`): every resource parses the same JSON
envelope shape through one helper. The PowerShell-side helpers and the
Go error types were never consolidated:

- 32 `internal/winclient/*.go` files each define their own `function
  Emit-OK` / `function Emit-Err` (plus a per-resource `Classify-*`).
  Envelope-protocol fixes (escaping, a new field, depth handling) must be
  repeated in ~32 scripts; past security fixes already had to chase
  hand-rolled copies (#173, #203).
- 44 `type XxxError struct` declarations, ~38 of them structurally
  identical (`Kind`, `Message`, `Context`, `Cause` plus `Error()`,
  `Unwrap()`, Kind-only `Is()`, `NewXxxError`, `IsXxxError` and sentinel
  vars). Only the `Kind` string-enum type and the resource prefix in
  `Error()` differ.
- Two script-input conventions coexist: `psQuote` interpolation into the
  script body (most resources) and a JSON document on stdin
  (`legacy_package`, `file`, `dsc_resource`, IIS secrets).

A single generic `Classify` with a pattern table cannot cover the
existing classifiers without redesign: they take incompatible shapes —
plain message strings (hostname, feature), `(Msg, FQEI)` pairs
(local_user), `$Record` objects inspected via `.Exception` / HResult
codes (file, eventlog), exit codes (winget). Envelope depths also drift
(`-Depth 8` vs `10` vs `16`) and IIS pins `InvariantCulture` while other
headers do not.

## Decision

Consolidation is incremental, one resource per batch, with no behaviour
change in any batch.

1. Shared Emit-only prelude. `internal/winclient/envelope_prelude.go`
   defines `psEnvelopePrelude`: the canonical `Emit-OK` / `Emit-Err`
   pair (`-Depth 8`, `$Ctx` nil-guard, `ConvertTo-Json -Compress` to
   `[Console]::Out`, the three preference pins). Migrated headers compose
   it by string concatenation (`psEnvelopePrelude + <rest>`), never by
   re-typing the functions. Classifiers and resource-specific helpers
   (`Read-*State`, `Invoke-*`, retry loops) stay per-resource until a
   later ADR designs their generic form; the generic-`Classify` idea from
   the issue is explicitly deferred for this reason.
2. Generic error type. `internal/winclient/resource_error.go` defines
   `ResourceError{Resource, Kind, Message, Context, Cause}` with
   `Error()` (`"<resource> [<kind>]: <message>[: <cause>]"`, matching the
   existing per-resource strings), `Unwrap()`, `(Resource, Kind)`-only
   `Is()`, plus `NewResourceError` / `IsResourceError` helpers. Later
   batches re-express each `*Error` as an alias or thin wrapper over
   `ResourceError` so provider handlers, `errors.Is` sentinels and `Is*`
   helpers keep compiling and behaving identically. Batch 1 rewrites no
   existing error type.
3. Input convention. JSON on stdin is the recommended channel for
   structured, large, or secret inputs (it removes quoting from the
   attack surface and avoids the UTF-16 base64 script-size blow-up);
   `psQuote` stays for short scalars. No new hand-rolled quoting
   (#173, #203). `psQuote` fixes continue to live in exactly one place.
4. Versioning rule. The prelude bytes are pinned by
   `TestPSEnvelopePrelude_Contents`. Changing the canonical bytes (Depth,
   parameter spelling — `winget_package` uses `$Msg` where the prelude
   uses `$Message` — preference pins) is a conscious, ADR-amended
   decision, never drive-by. Where a payload needs deeper serialisation
   than `-Depth 8` (today: `file` at 16, `legacy_package` at 10), the
   migrated header keeps its own depth at the call site until a batch
   canonicalises it with fixture proof.
5. Guard test. `TestPSEnvelopePrelude_NoNewDefinitions` scans non-test
   `internal/winclient/*.go` for `function Emit-(OK|Err)` definitions
   (leading whitespace tolerated) outside `envelope_prelude.go` against an explicit allowlist of not-yet-
   migrated files. Each migration batch shrinks the allowlist. The two
   pre-existing shared headers (`iis_common.go`, `storage_common.go`) are
   grandfathered in the allowlist until they migrate to the prelude.
6. Batch 1 (this ADR). ADR text + prelude const + `ResourceError`
   scaffolding + pilot migration of `hostname` (small, string classifier,
   no stdin secrets; its header is byte-identical after composition) +
   guard test. No provider-layer, schema, or `docs/` changes.

## Consequences

- Envelope fixes land once; each new resource starts from the prelude
  and review focuses on logic instead of copies.
- Header-content tests that assert the old duplicated strings are updated
  only in the resource's own migration batch ("moved string" edits stay
  distinguishable from logic changes); the pilot (`hostname`) needs no
  such edit because no hostname test pins the Emit bytes.
- `docs/` stays generated (`make docs`); this record lives in `adr/` on
  purpose, outside the drift gate.
- Later batches (generic classifier design, per-resource error aliases,
  `iis_common` / `storage_common` migration, stdin conversions) each get
  their own plan against this ADR; none may change wire behaviour without
  fixture proof.
