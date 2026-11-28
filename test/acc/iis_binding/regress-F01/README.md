# Regression F01 — parallel same-site binding race (NullReference)

## Context

Finding F01 (run `2611281430`, scenario `10-inputs-host-normalization`) :
two `windows_iis_binding` resources on one site in a single config race
each other under Terraform's default parallelism. The loser fails with a
raw `Object reference not set to an instance of an object` — on create
(first apply) and again on parallel destroy. An identical serial retry
passes both times, proving transience. Reproduction minimale in
`work/acc/iis_binding/2611281430/repro/F01`.

## Cause (no code changed here — pointer for `provider-coder`)

`runBindingWrite` in `internal/winclient/iis_binding.go` (lines ~302-326)
only retries the `IISConfigChangedOnDisk` ("file has changed") flake; the
concurrent-writer null-ref from simultaneous `New-WebBinding` /
`Remove-WebBinding` against one site's `applicationHost.config` is
returned immediately. `Delete` already tolerates a concurrent-destroy race
(lines ~750-768, 2026-11-17 note); `Create` has no equivalent tolerance.

Suggested fix (pick one, do not combine without review): extend
`runBindingWrite` to retry transient concurrent-writer
NullReference/Object-reference failures with the same bounded
attempts/backoff, or serialise same-site binding writes. Documenting
`-parallelism=1` is not a fix: default parallelism must work.

## Reproduction steps (LAB 201 -> LAB 203)

Terraform runs on 201 with `TF_CLI_CONFIG_FILE` pointing at the run's
`terraform.rc` (dev_override to the run's provider binary), per
`acc/lab-runner`. The prefix is configurable via
`-var site_prefix=...` (default `tfacc`).

1. `terraform init -input=false -no-color` — expected: exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — expected after
   fix: exit 0, both bindings present (repeat several times: the race is
   timing-dependent, a single green run is weak evidence).
3. `terraform plan -detailed-exitcode -input=false -no-color` — expected:
   detailed-exit 0, "No changes".
4. `terraform destroy -auto-approve -input=false -no-color` — expected:
   exit 0, no retry needed.
5. Verify on 203: no `<prefix>-regress-f01` bindings or site remain
   (`Get-WebBinding -Name '<prefix>-regress-f01'` empty,
   `Get-Website -Name '<prefix>-regress-f01'` absent).

## Expected

- No `Object reference not set` on create or destroy under default
  parallelism; apply/plan/destroy converge without manual retry.
