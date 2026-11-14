# ADR-0012 — Provider-wide partial-failure contract (persist partial state, taint by default)

- Status: Accepted
- Date: 2026-11-14
- Supersedes: none
- Relates to: issue #344; issue #341 (windows_service precedent)

## Context

`windows_service` (issue #341) established the provider's first partial-failure
rule: when a `winclient` Create or Update call returns a non-nil state together
with an error (for example, runtime-state reconciliation failing after
`New-Service` already registered the service), the handler persists the
observed state via the existing `modelFromState` projection and then reports
the error diagnostic, so the resource is marked tainted instead of being
dropped from state. A nil state on error (for example, the `already_exists`
pre-flight) stays error-only.

The remaining resources each had their own ad-hoc behaviour on error — most
discarded whatever the client returned and reported error-only. Issue #344
asks for one provider-wide contract so operators get the same tainted-state
recovery story everywhere.

## Decision

Persist-partial-state is the default. For every resource Create and Update
error branch:

1. When the `winclient` call returns a non-nil state alongside the error, the
   handler projects it with the resource's existing state builder
   (`modelFromState` / `stateToModel` / `iisSiteStateToModel` /
   `iisAppPoolStateToModel` / `applySmbShareInfo` / `stateFromUser` /
   `firewallStateToModel` / `applyState`), preserves the user-configured
   `timeouts` (and ForceNew identity fields where the success path already
   does), persists it with `resp.State.Set`, and then appends the error
   diagnostic. The resource is therefore tainted (create) or keeps its partial
   state (update); fixing the cause and re-applying reconciles it.
2. A nil state on error stays error-only: the handler reports the diagnostic
   and touches no state. This is also what keeps the `already_exists`
   pre-flight error-only — every pre-flight returns a nil state, so no
   `already_exists` (or other pre-validation) failure can persist state by
   accident.
3. On Update, credential and rotation markers (`service_password` /
   `service_password_wo_version`, `principal.password` /
   `principal.password_wo_version`, `identity_password_wo_version`,
   local-user `password` / `password_wo_version`) are restored from prior
   state on the partial-failure path — exactly as the success path carries
   them forward, but from `prior` instead of `plan`. A failed rotation must
   not advance the stored version marker, otherwise the retry would no longer
   diff and the rotation would be silently lost.
4. No `winclient` PowerShell script is changed to re-read after a failure.
   When the script cannot observe the host (for example, `iis_site` Create
   deletes the half-created site best-effort and returns an error with nil
   state), the provider reports error-only. A nil state on error does not
   guarantee nothing was created: config-mutation failures after the object
   was registered can leave an orphan that must be removed out-of-band or
   re-adopted with `terraform import`. Each resource schema documents this
   per-resource import/cleanup path.

Rollback stays a narrow, explicitly documented exception: a resource may roll
back instead of persisting partial state only when the rollback itself is
reported (rollback-success reporting), so the operator can tell "rolled back
cleanly" apart from "orphan possible". `iis_site` Create is the current
example (script-side `Remove-Website` best-effort on failure, nil state
returned). Anything that cannot be rolled back, or whose rollback is not
reported, follows the persist-partial-state default.

## Consequences

- New error branches follow the `windows_service` shape (`if state != nil {
  build model; resp.State.Set }; add diag; return`) using each resource's
  existing projection — no new winclient surface, no re-reads.
- Schema `MarkdownDescription` notes on each resource describe the
  tainted-vs-orphan outcomes and the import/cleanup path, mirroring the
  `windows_service` wording but resource-specific.
- `docs/` stays generated: schema text changes flow through `make docs`
  (`go generate ./...`), never hand-edited.
- Tests inject a fake client returning `(valid state, error)` and assert
  `resp.State` is non-empty plus an error diagnostic, with a nil-state
  control asserting error-only; Update tests additionally assert the
  credential/version markers come from prior state.
