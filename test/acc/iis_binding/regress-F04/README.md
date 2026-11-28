# Regression F04 — bracketed ip_address diagnostic must name brackets

## Context

Finding F04 (run `2611281430`, scenario `15-inputs-rejected-network`
step6) : `ip_address = "[::1]"` is correctly rejected at plan time
(brackets belong to the `bindingInformation` rendering only), but the
diagnostic text does not contain the word "bracket", so the scenario's
`/(?i)bracket/` regex missed. 5 of 6 rejection steps matched; only this
wording diverged. Reproduction minimale in
`work/acc/iis_binding/2611281430/repro/F04`.

## Cause (no code changed here — pointer for `provider-coder`)

`iisBindingIPAddressValidator.ValidateString`
(`internal/provider/resource_windows_iis_binding.go`, lines ~269-293)
emits the generic "must be `*` or a valid IPv4/IPv6 address" message for
bracketed input (it fails `netip.ParseAddr`), while the winclient twin
`NormalizeIISBindingIPAddress`
(`internal/winclient/iis_binding_types.go`, lines ~214-216) has an
explicit bracket branch ("must be `*` or a bare IP address without
brackets"). Plan-time and apply-time diagnostics disagree.

Suggested fix: add an explicit bracket branch to the plan-time validator
mirroring the winclient message ("without brackets"), keeping both layers
aligned.

## Reproduction steps (LAB 201 -> LAB 203)

Terraform runs on 201 with `TF_CLI_CONFIG_FILE` pointing at the run's
`terraform.rc` (dev_override to the run's provider binary), per
`acc/lab-runner`. No host contact occurs; nothing is created.

1. `terraform init -input=false -no-color` — expected: exit 0.
2. `terraform apply -auto-approve -input=false -no-color` — expected after
   fix: exit 1 with a diagnostic matching `/(?i)bracket/`. Before fix:
   exit 1 but the message only says "must be `*` or a valid IPv4/IPv6
   address".
3. Verify on 203: site `<prefix>-regress-f04-nv` absent
   (`Get-Website` empty) — belt and braces, nothing should exist.

## Expected

- Rejection stays fail-closed before any host contact, and the diagnostic
  explicitly names brackets.
