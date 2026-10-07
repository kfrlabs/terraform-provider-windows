# Lab-container Terraform fixtures

Standalone `.tf` configurations for exercising the provider by hand against
the throwaway `tfacc-win` container (`test/windows-container/`), as a
complement to the Go acceptance suite:

- The Go suite (`*_acc_test.go`, driven by `testacc-lab-container.yml` /
  `testacc-windows.yml`) asserts narrow, single-resource behavior and tears
  everything down per test.
- This directory is a long-lived, hand-applied workspace that wires several
  resources together the way a real configuration would (a service account
  granted group membership, a file secured right after being written, a
  scheduled task driven by that account, etc.), so it catches interaction
  bugs between resources that isolated unit-style tests cannot.

It targets the **same** container as `testacc-lab-container.yml`— reuse it,
do not stand up a second one, or the two test paths fight over the same
mutable machine state (local users, firewall rules, registry keys, ...).

## Layout

One file per resource family, all applied together from this directory:

| File | Resource(s) |
| --- | --- |
| `provider.tf` | Provider + required_providers block |
| `variables.tf` | Connection vars + feature flags |
| `identity.tf` | `windows_local_group`, `windows_local_user`, `windows_local_group_member` |
| `storage.tf` | `windows_file`, `windows_file_acl`, `windows_registry_value`, `windows_environment_variable` |
| `network.tf` | `windows_firewall_rule` |
| `scheduling.tf` | `windows_scheduled_task` (driven by the service account from `identity.tf`) |
| `service.tf` | `windows_service` (reconfigures a service already present in the image) |
| `packages.tf` | `windows_legacy_package`, `windows_winget_package` — gated behind `enable_network_tests`, see below |
| `datasources.tf` | One data source block per sibling resource above, cross-checked against the resource's own state |
| `outputs.tf` | Everything worth eyeballing after `apply` |

## Running it

```bash
cd test/terraform
cp terraform.tfvars.example terraform.tfvars   # edit if your container differs
export WINDOWS_PASSWORD='<temporary-lab-password>'
export TF_VAR_svc_password='<different-temporary-user-password>'
terraform init
terraform plan
terraform apply
# ... inspect, re-apply after edits, iterate ...
terraform destroy
```

Defaults in `terraform.tfvars.example` match the container as documented in
`test/windows-container/README.md` (`WINDOWS_HOST=<lab host>`, port `2222`,
user `tfacc`). Point `windows_host` at your own container/host if different.
Supply credentials out of band with `WINDOWS_PASSWORD` (or
`WINDOWS_PRIVATE_KEY_PATH`) and `TF_VAR_svc_password`; do not commit them.

### Which provider build this runs against

`provider.tf` asks for `~> 0.0`, but the fixture uses provider config this
file set only has on `main` (`port`, `insecure_ignore_host_key`) and the
newest **published** release on the registry can lag `main`. If
`terraform init` pulls a release without those attributes, point Terraform at
a local build instead:

```bash
make build   # installs terraform-provider-windows into $(go env GOPATH)/bin

cat >> ~/.terraformrc <<'EOF'
provider_installation {
  dev_overrides { "kfrlabs/windows" = "/absolute/path/to/$(go env GOPATH)/bin" }
  direct {}
}
EOF

cd test/terraform
terraform plan    # dev_overrides skips init and the lock file entirely
```

`dev_overrides` is what the fixture was validated with (Terraform 1.13,
provider built from this branch). No `.terraform.lock.hcl` is committed, so
there is nothing to unpin; `terraform.tfvars` (the real password) and
`.terraform/` are gitignored.

## Feature flags (`variables.tf`)

Some resources mutate machine-global state or need outbound network access
the container may not have; both are opt-in so a plain `terraform apply`
stays fast and side-effect-free beyond what this workspace itself declares:

- `enable_network_tests` (default `false`) — `packages.tf`
  (`windows_legacy_package` download-from-URL, `windows_winget_package`).
  Requires the container to reach the internet and, for
  `windows_winget_package`, the App Installer package to be present in the
  image — it generally is **not** in a bare `servercore:ltsc2025` image; see
  the "Known container limitations" section below before filing an issue
  about it.
- `enable_feature_test` (default `false`) — installing a Windows feature via
  `windows_feature` inside a container is slow (DISM) and some roles are
  simply unavailable in a container (no underlying image/payload). Flip it on
  only when you specifically need to validate that resource.

## Known container limitations

Not provider bugs — properties of running inside a Windows container that
would also apply to anyone else's container-based test rig. Tracked here so
a fresh run does not get misreported as a regression:

- `windows_winget_package` needs `winget.exe` (the App Installer package),
  which `mcr.microsoft.com/windows/servercore:ltsc2025` does not ship. See
  `packages.tf` for the gate.
- `windows_scheduled_task` needs the Task Scheduler service running; verify
  with `Get-Service Schedule` on the container before assuming a resource
  bug if it fails to apply.
- `windows_feature`: most server roles have no payload inside a minimal
  container image (DISM has nothing to pull from), so installs that work
  fine on a real host can fail here with "source files could not be found".
  Use `windows_feature.source` pointed at a mounted SxS folder, or test this
  resource against a VM instead of the container.

Any failure that is **not** explained by one of the above is a real finding:
open a GitHub issue (see the repository's issue templates) with the
`terraform apply` output, the resource block, and whether it reproduces
against a non-containerized Windows host.
