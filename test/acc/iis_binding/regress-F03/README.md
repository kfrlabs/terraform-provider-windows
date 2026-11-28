# Regression F03 — warning-only store without certificate ("inconsistent result")

## Context

Finding F03 (run `2611281430`, scenario `14-inputs-store-warning`) :
an https binding with `certificate_store_name = "WebHosting"` and no
`certificate_thumbprint` emits the expected
"certificate_store_name without a certificate" warning, the host binding
IS created (`https *:18134:...`, sslFlags 0), but apply still fails with
"Provider produced inconsistent result after apply"
(`.certificate_store_name` planned `WebHosting`, read back `My`).
Reproduction minimale in `work/acc/iis_binding/2611281430/repro/F03`.

## Cause (no code changed here — pointer for `provider-coder`)

`modelToIISBindingCreateInput`
(`internal/provider/resource_windows_iis_binding.go`, lines ~464-492)
only forwards the store alongside a thumbprint, and
`parseIISBindingState` yields an empty store when no certificate is bound
(`internal/winclient/iis_binding.go`, lines ~417-424); then
`iisBindingStateToModel` (lines ~713-718) maps the empty observed store to
`"My"` while the plan still holds `"WebHosting"`.

Suggested fix (spec-aligned: the scenario documents warn-and-apply): when
no certificate is bound (observed thumbprint empty), project the planned
`certificate_store_name` spelling into state instead of defaulting to
`"My"` — the store carries no host meaning without a certificate, as the
warning itself states.

## Reproduction steps (LAB 201 -> LAB 203)

Terraform runs on 201 with `TF_CLI_CONFIG_FILE` pointing at the run's
`terraform.rc` (dev_override to the run's provider binary), per
`acc/lab-runner`. The prefix is configurable via
`-var site_prefix=...` (default `tfacc`).

1. `terraform init -input=false -no-color` — expected: exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — expected after
   fix: exit 0 WITH the "certificate_store_name without a certificate"
   warning and no "inconsistent result" error. Before fix: exit 1 with
   "inconsistent result after apply".
3. `terraform plan -detailed-exitcode -input=false -no-color` — expected:
   detailed-exit 0, "No changes".
4. `terraform destroy -auto-approve -input=false -no-color` — expected:
   exit 0.
5. Verify on 203: `Get-WebBinding -Name '<prefix>-regress-f03'` empty,
   site removed.

## Expected

- Warning-only path converges: warn, apply cleanly, empty plan, clean
  destroy — never "inconsistent result after apply".
