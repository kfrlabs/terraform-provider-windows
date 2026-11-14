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

Consolidation is incremental, one resource per batch, with no logic
change in any batch (v2 adds invariant-culture pins to the batch-1/2 wire
bytes; rendering-only, see rule 4).

1. Shared Emit-only prelude. `internal/winclient/envelope_prelude.go`
   defines `psEnvelopePrelude`: the canonical `Emit-OK` / `Emit-Err`
   pair (`-Depth 8`, `$Ctx` nil-guard, `ConvertTo-Json -Compress` to
   `[Console]::Out`, the three preference pins, and since v2 the
   InvariantCulture thread pins). Migrated headers compose
   it by string concatenation (`psEnvelopePrelude + <rest>`), never by
   re-typing the functions. The matching loop for string classifiers is
   shared since batch 5 (`Classify-ByPatterns`: ordered [pattern, kind]
   rows, single-regex OR or array AND, first match wins; table data stays
   per-resource): `hostname` is the pilot, proven equivalent over a
   21-message corpus on the Windows fixture. Classifiers over $Rec
   objects with .Exception/HResult, exit-code classifiers and
   resource-specific helpers (`Read-*State`, `Invoke-*`, retry loops)
   stay per-resource.
2. Generic error type. `internal/winclient/resource_error.go` defines
   `ResourceError{Resource, Kind, Message, Context, Cause}` with
   `Error()` (`"<resource> [<kind>]: <message>[: <cause>]"`, matching the
   existing per-resource strings), `Unwrap()`, `(Resource, Kind)`-only
   `Is()`, plus `NewResourceError` / `IsResourceError` helpers. Batch 5
   piloted the alias pattern on `hostname` (`type HostnameError =
   ResourceError`, untyped kind constants so all call sites compile
   unchanged, sentinels carry the `windows_hostname` resource key to
   preserve `errors.Is` matching); batch 6 rolled it out to all 37
   remaining per-resource types (`ManagementPathError` uses
   `"management_path"`) plus `LegacyPackageError` (whose Kind was
   already a plain string). Wire format is byte-identical everywhere;
   `errors.Is` matching is preserved because every constructor and every
   struct literal now carries the resource key.
3. Input convention. JSON on stdin is the recommended channel for
   structured, large, or secret inputs (it removes quoting from the
   attack surface and avoids the UTF-16 base64 script-size blow-up);
   `psQuote` stays for short scalars. No new hand-rolled quoting
   (#173, #203). `psQuote` fixes continue to live in exactly one place.
4. Versioning rule. The prelude bytes are pinned by
   `TestPSEnvelopePrelude_Contents` and `TestPSClassifyPrelude_Contents`.
   Changing the canonical bytes (Depth, parameter spelling, preference/culture pins,
   classifier table shape) is a conscious, ADR-amended decision, never
   drive-by. Batch 5 resolved the last spelling divergence (`winget_package`
   `$Msg` -> canonical `$Message`; all call sites were positional). Where a payload needs deeper serialisation
   than `-Depth 8` (e.g. `file`/`registry_value` at 16, `legacy_package`
   at 10, `scheduled_task_scripts` at 12, plus other Depth-10 headers),
   the migrated header keeps its own depth at the call site only until a
   batch proves a lower depth safe. Proven on the Windows fixture
   (PS 5.1, fr-FR Server 2025): Depth 16/12/10 vs 8 produce
   byte-identical JSON for the deepest realistic payloads of every
   migrated family (dicts, string lists, task payloads to depth 4, DSC
   File/Registry Test+Get at depth <= 3, deepest documented generic DSC
   shape at depth 6 — all below the ceiling of 8). v2 (batch 3) adds the
   InvariantCulture thread pins, following
   the IIS/storage precedent: error text and .NET formatting stay stable
   regardless of host locale, which is the point of a machine-parseable
   envelope. The batch-1/2 headers gain the two lines through composition
   (benign: invariant formatting affects rendering only, never logic).
5. Guard test. `TestPSEnvelopePrelude_NoNewDefinitions` scans non-test
   `internal/winclient/*.go` for `function Emit-(OK|Err)` definitions
   (leading whitespace tolerated) outside `envelope_prelude.go` against an
   explicit allowlist. Batch 4c migrated the last entry
   (`dsc_resource_scripts.go`); the allowlist is intentionally empty.
   Later batches (per-resource error aliases, stdin conversions) each get
   their own plan against this ADR; none may change wire behaviour
   without fixture proof.
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
- Later batches (stdin conversions, rolling out `Classify-ByPatterns`
  to the remaining string classifiers) each get their own plan against
  this ADR; none may change wire behaviour without fixture proof.
  Batches 2-4 migrated every
  header whose Emit pair was byte-identical or provably equivalent
  (32 files share the prelude; the DSC depth downgrade was proven on the
  Windows fixture).
