# terraform-cli — full resource + data source coverage via the Terraform CLI

Exercises via **Terraform only** (no `go test`): all 15 resources and all 11
data sources, with data sources cross-checked against resource state and
`check` blocks failing the `apply` on divergence. Validated end-to-end on
2026-10-04 against the `tfacc-win` lab container (Server 2025,
PowerShell 5.1 only, no `pwsh`): **19/19 resources applied, 5/5 cross-checks
PASS, second plan empty, destroy clean.**

## Coverage

| File | Content |
| --- | --- |
| `01-identity.tf` | `windows_local_group`, `windows_local_user`, `windows_local_group_member` |
| `02-storage.tf` | `windows_directory` (x3), `windows_file` (x2), `windows_file_acl` |
| `03-registry-env.tf` | `windows_registry_value` (REG_SZ, EXPAND_SZ, MULTI_SZ, DWORD, QWORD, BINARY), `windows_environment_variable` (machine + user) |
| `04-network.tf` | `windows_firewall_rule` (inbound allow + outbound block, gated) |
| `05-scheduling-service.tf` | `windows_scheduled_task` (SYSTEM principal, `settings` + trigger duration), `windows_service` |
| `06-packages-feature-hostname.tf` | `windows_legacy_package`, `windows_winget_package`, `windows_feature`, `windows_hostname` (all gated) |
| `07-datasources.tf` | All 11 data sources (gated ones with `count`, like the resources) |
| `08-outputs-checks.tf` | Outputs + 4 `check` resource-vs-data blocks that fail the `apply` |
| `mock.tftest.hcl` | `terraform test` with mocked provider, 100% offline |

`windows_file` / `windows_file_acl` / `windows_directory` /
`windows_legacy_package` have no data source in the provider — nothing to
cross-check for them.

## Flags (`variables.tf`)

- `enable_firewall_tests` (default `false`) — firewall rules + data source.
  Off in containers (see limitation L1). Enable on a full Windows host/VM.
- `enable_network_tests` (default `false`) — `windows_legacy_package`
  (URL download) + `windows_winget_package` (+ data source). Needs container
  internet + App Installer in the image (absent from bare
  `servercore:ltsc2025`).
- `enable_feature_test` (default `false`) — `windows_feature` (+ data
  source). Slow (DISM), payload often missing in containers.
- `enable_hostname_test` (default `false`) — `windows_hostname` rename.
  Makes the machine reboot-pending: dedicated throwaway host only.

## Run

```bash
cd test/terraform-cli
cp terraform.tfvars.example terraform.tfvars   # adjust the target host/port/user
export WINDOWS_PASSWORD='<temporary-lab-password>'
export TF_VAR_svc_password='<different-temporary-user-password>'
./run-tests.sh            # offline: init, fmt, validate, mocked test
./run-tests.sh --apply    # + plan, apply, output verify, empty-plan check, destroy
```

For key-based auth, set `WINDOWS_PRIVATE_KEY_PATH` instead of `WINDOWS_PASSWORD`.
Keep credentials in environment variables or untracked local files; never add
them to the example tfvars or repository. `--apply` needs the Windows target
from `terraform.tfvars` (`test/windows-container/README.md` to raise `tfacc-win`). The final
`destroy` cleans up; `test_suffix` isolates this workspace from the historic
`test/terraform` fixtures and the Go suite on a shared host.

The provider binary used here is a **linux_arm64** build from the same
commit (the Windows `.exe` in `dist/` cannot run on the Linux CI host):

```bash
docker create --name b tfwin-provider-windows:build \
  sh -c 'cd /src && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=0.1.0" -o /tmp/terraform-provider-windows .'
docker start -a b
docker cp b:/tmp/terraform-provider-windows /tmp/opencode/plugins/terraform-provider-windows
docker rm b
# ~/.terraformrc: dev_overrides { "kfrlabs/windows" = "/tmp/opencode/plugins" }
```

## Windows build (via Docker)

```bash
docker build -f Dockerfile.windows -t tfwin-provider-windows:latest .
docker create --name tfwin-extract tfwin-provider-windows:build
docker cp tfwin-extract:/out/terraform-provider-windows_v0.1.0_windows_amd64.exe ./dist/
docker rm tfwin-extract
```

The final `scratch` stage cannot be `docker create`d (no command): extract
from the intermediate `:build` image (`build-windows` target) instead. The
`unit-tests` stage (`go vet` + `go test -short`) runs inside the same build
and passed. Output: `dist/terraform-provider-windows_v0.1.0_windows_amd64.exe`
(21 MB, `MZ` / PE verified, deterministic — same SHA256 as the previous
build for the same version).

## Historical findings (live apply, 2026-10-04)

These findings describe the source tree as it stood on 2026-10-04. The
2026-10-06 E2E campaign replayed the password and task paths against Windows
Server 2025 PowerShell 5.1 and corrected the regressions noted below.

- **[#99](https://github.com/kfrlabs/terraform-provider-windows/issues/99) — WriteOnly values previously failed on Create.**
  The current resources overlay WriteOnly values from `req.Config` at apply
  time. This campaign verified `windows_local_user.password_wo`,
  `windows_scheduled_task.principal.password_wo` create/rotation, and
  `windows_service.service_password_wo` create/update. Terraform states were
  checked to ensure the plaintext was absent.
- **[#101](https://github.com/kfrlabs/terraform-provider-windows/issues/101) — Password principals previously failed on PowerShell 5.1.**
  This campaign found that `Register-ScheduledTask`/`Set-ScheduledTask`
  cannot combine `-Principal` with `-Password`; the provider now uses their
  `-User`/`-Password` parameter sets and preserves the principal identity.
  Password principal create, version rotation, description update, idempotence,
  and destroy all passed on the PS 5.1 test host.
- **[#102](https://github.com/kfrlabs/terraform-provider-windows/issues/102) — non-ASCII descriptions do not round-trip.** `—` (em-dash)
  in `description` comes back as `-`, tripping "inconsistent result after
  apply". Same for any non-ASCII sent through the 5.1 transport.
  **Workaround:** ASCII-only descriptions in the fixture.
  **Fix (`fix/102-utf8-console-output-encoding`):** both bootstraps
  (`oneShotBootstrap`, `psReplBootstrap`) force `[Console]::OutputEncoding` /
  `$OutputEncoding` to UTF-8 before any read/write, and the Go/SSH layer is
  pinned byte-preserving by the corpus probe
  (`TestTransportNonASCIIOutputRoundTripsBothTransports`: em-dash, accented,
  CJK on both transports) plus the bootstrap guards in `client_test.go`.
  Re-run `./run-tests.sh --apply` with a non-ASCII description to confirm
  end-to-end. State written while mangled (e.g. `-` stored for `—`) shows a
  one-time diff as the true value reads back — expected, accept and apply
  once. Must not regress the persistent-`pwsh` path.
   Verified-vs-assumed: the `sc.exe qc` / `qdescription` path in
   `windows_service` read-state is only assumed fixed — `sc.exe` output may
   still decode OEM bytes as UTF-8 (`U+FFFD`). Requires a live 5.1 e2e run
   with a non-ASCII service description to inspect for `U+FFFD`; if it
   shows, future options are codepage 65001 around the `sc.exe` calls or
   switching to `Get-Service` / `Get-CimInstance`. Note: one-shot stdin via
   `[Console]::In.ReadToEnd` remains OEM while the persistent transport is
   base64 — out of scope for #102, tracked as a follow-up, no logic change.
- **L1 — no Windows Firewall in containers.** `New-NetFirewallRule` fails
  with "no more endpoints available from the endpoint mapper" (WFAS
  unavailable under container isolation). Gated behind
  `enable_firewall_tests`.
- **L2 — data source needs `depends_on` for read-after-write.**
  `data.windows_local_group_member` references only group/user names, so
  Terraform may read it before the membership resource is applied
  ("member not found"). Fixed with an explicit `depends_on` on the member
  resource — same latent race exists in `test/terraform/datasources.tf`.
- **Expected, not a bug:** destroying all `windows_registry_value`
  resources leaves the (now empty) parent key behind — Delete removes
  values, not keys. The suite's destroy leaves the target clean apart from
  that empty key (removed manually after the run).

## Fixed since that run

- **[#100](https://github.com/kfrlabs/terraform-provider-windows/issues/100) — `settings.execution_time_limit` passed raw to
  `New-ScheduledTaskSettingsSet -ExecutionTimeLimit`**, which requires a
  `TimeSpan` ("Cannot convert value PT72H"), so any `settings` block failed
  Create. The generated PowerShell now converts the configured ISO 8601 value
  with `[System.Xml.XmlConvert]::ToTimeSpan`. The accepted sets differ per
  attribute:
  - `settings.execution_time_limit` goes through `ToTimeSpan`, which would
    approximate year and month components as 365- and 30-day intervals, so it
    accepts XSD durations of days or less (`PT4H`, `PT72H`, `PT0S`, `P3D`,
    `PT1440M`). It is compared by duration, so an equivalent re-read spelling
    does not drift.
  - trigger `execution_time_limit` is a string-typed CIM property assigned
    and read back verbatim, so it accepts the full XSD grammar
    (`P3D`, `P1DT2H`, `P3DT0H0M0S`, `P1M4DT2H5M`).
  - trigger `delay` is only valid for `AtLogon`, `AtStartup`, and `OnEvent`;
    the resource now rejects it for `Once`, `Daily`, and `Weekly` rather than
    silently dropping it on Windows.

  The fixture declares a settings block, a daily trigger duration, and an
  AtStartup delay; the 2026-10-06 E2E run verified all three on PS 5.1.
