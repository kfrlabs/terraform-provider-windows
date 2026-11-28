# Regression F02 — IPv6 canonical mismatch (write unbracketed, read bracketed)

## Context

Finding F02 (run `2611281430`, scenario `11-inputs-ip-variants`) :
`ip_address = "::1"` fails deterministically. `Create` writes the
host-native unbracketed form (`::1:18125:...` in `applicationHost.config`,
verified on 203) but reads back the bracketed canonical form
(`[::1]:18125:...`), so the literal `-eq` match in `Get-BindingData`
misses and apply fails with "was not found on site after creation" —
even with `-parallelism=1` (serial probe in the run, so NOT the F01
race). The binding IS on the host (orphan, absent from state), so the
identical retry fails with "Cannot add duplicate collection entry".
Reproduction minimale in `work/acc/iis_binding/2611281430/repro/F02`.

## Cause (no code changed here — pointer for `provider-coder`)

`bindingScriptVars` passes the bare address to `New-WebBinding
-IPAddress $WantedIP` (`internal/winclient/iis_binding.go`, line ~529)
while `$BindingInfo` is the bracketed canonical rendering
(`BuildIISBindingInformation`, `internal/winclient/iis_binding_types.go`
lines ~277-282). Every match path (`Get-BindingData` line ~117, Create
pre-checks lines ~517-522, Update line ~647, Delete line ~738) compares
raw `bindingInformation` strings with `-eq`, so the host's unbracketed
form never equals the canonical form.

Suggested fix: compare parsed `(ip, port, host)` tuples instead of raw
strings on every match path — canonicalise the host-enumerated
`bindingInformation` via `Get-BindingParts`/`BuildIISBindingInformation`
before comparing, so unbracketed host forms equal the bracketed canonical
form. Add an IPv6 round-trip unit case covering write-form vs read-form.

## Reproduction steps (LAB 201 -> LAB 203)

Terraform runs on 201 with `TF_CLI_CONFIG_FILE` pointing at the run's
`terraform.rc` (dev_override to the run's provider binary), per
`acc/lab-runner`. The prefix is configurable via
`-var site_prefix=...` (default `tfacc`).

1. `terraform init -input=false -no-color` — expected: exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — expected after
   fix: exit 0. Before fix: exit 1, "was not found on site after
   creation" (`-parallelism=1` does NOT help — that is the point).
3. `terraform plan -detailed-exitcode -input=false -no-color` — expected:
   detailed-exit 0, "No changes"; `binding_information` is
   `[::1]:18243:<prefix>-regress-f02-v6.example.com`.
4. `terraform destroy -auto-approve -input=false -no-color` — expected:
   exit 0, no orphan left (before fix, manual `Remove-WebBinding` of the
   unbracketed `::1:...` form plus `Remove-Website` is required).
5. Verify on 203: `Get-WebBinding -Name '<prefix>-regress-f02'` empty and
   `applicationHost.config` holds no `::1:18243:` entry.

## Expected

- Apply/plan/destroy converge with no orphan and no duplicate-collection
  error; `binding_information` carries the bracketed canonical IPv6 form.
