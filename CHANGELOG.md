# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- winclient transport: PowerShell scripts are no longer inlined on the command
  line via `-EncodedCommand`. Only a fixed bootstrap is passed on the command
  line; the real script (UTF-16LE base64) is streamed on stdin, keeping the
  command line at a constant ~600 chars. This resolves `The command line is too
  long.` failures on larger scripts — notably the `windows_service`,
  `windows_firewall_rule`, `windows_local_group_member` and
  `windows_registry_value` data-source reads — while preserving UTF-16LE
  fidelity for non-ASCII values. (#39)

### Internal

#### Changed

- Data sources normalization: aligned acceptance test naming to `TestAccWindows<R>DataSource_<Case>`,
  removed the unused `client *winclient.Client` field from data sources that only need their typed sub-client,
  unified the `schema` import alias in `datasource_windows_environment_variable.go`,
  moved `windowsScheduledTaskDSModel` and friends from `resource_windows_scheduled_task.go` to
  `datasource_windows_scheduled_task.go`, and sorted `provider.DataSources()` alphabetically.
- Resources normalization: renamed hostname test files to match the project convention
  (`*_test.go` for unit, `*_acc_test.go` for acceptance), removed the unused `client *winclient.Client`
  field from 9 resources whose Configure stored it without ever reading it back, aligned
  `windows_local_group_member` acceptance test names to `TestAccWindows<R>_<PascalCase>`,
  and sorted `provider.Resources()` alphabetically.

### Data Sources

#### Added

- `windows_winget_package` data source: read-only lookup of a single
  winget-managed package on a remote Windows host via WinRM and the
  `Microsoft.WinGet.Client` PowerShell module. Reuses the twin resource's
  `winclient.WingetPackageClient.Read` pipeline (Equals(Id) filter,
  ARP-only detection, single retry on `source_unreachable`) and surfaces
  an explicit `not_found` Terraform error when the package is absent
  from both the catalog and ARP — data sources never silently
  produce empty state.

### Added

- **WriteOnly credential attributes (Tier 3, TPF v1.14.1)** on every
  resource that previously persisted plaintext passwords in
  `terraform.tfstate`:
  - `windows_local_user.password_wo` (paired with the existing
    `password_wo_version` rotation counter).
  - `windows_service.service_password_wo` (paired with the legacy
    `service_password`; no version counter is needed because the
    WriteOnly value is re-read from configuration on every plan and
    forwarded to `Set-Service` unconditionally — re-supplying the same
    value is naturally idempotent).
  - `windows_scheduled_task.principal.password_wo` (re-uses the
    existing `principal.password_wo_version` counter as the rotation
    trigger; the Update path was already version-gated so no
    server-side change was needed).

  All three new attributes are declared with `WriteOnly: true,
  Sensitive: true` and are **never written to `terraform.tfstate`** —
  the framework strips the value from state automatically after each
  CRUD response. They are mutually exclusive with their legacy
  state-persisted counterpart (`resourcevalidator.Conflicting` at the
  resource level for `local_user` / `service`, inline check inside
  `scheduledTaskPrincipalCrossFieldValidator` for `scheduled_task`
  because the attributes live inside a nested block).

  The legacy `password` / `service_password` / `principal.password`
  attributes are now flagged with a `DeprecationMessage` pointing at
  the WriteOnly replacement; `terraform plan` will surface the
  deprecation warning on every run until the operator migrates. The
  attributes themselves remain functional — removal is scheduled for
  v2.x.

  Migration is one-line per credential and does not require a state
  rewrite:

  ```hcl
  # Before (legacy, persisted in state)
  resource "windows_local_user" "svc" {
    name     = "svc-app"
    password = var.svc_password   # <- persisted
  }

  # After (Tier 3, never persisted)
  resource "windows_local_user" "svc" {
    name                = "svc-app"
    password_wo         = var.svc_password   # <- WriteOnly
    password_wo_version = 1                  # increment to rotate
  }
  ```

- **Structured `tflog.Debug` instrumentation on every CRUD hot path**
  for the eight resources that previously had zero `tflog` coverage
  (`windows_service`, `windows_scheduled_task`, `windows_registry_value`,
  `windows_local_user`, `windows_local_group`, `windows_feature`,
  `windows_legacy_package`, `windows_winget_package`). Payloads always
  include the natural identifier (name, id, sid, hive+path+name, or
  package_id+source) and never include sensitive values — passwords
  are represented exclusively by their `password_wo_version` counter.
  Notable: `windows_scheduled_task` Update logs a computed
  `password_rotated` boolean so operators can audit credential
  rotations from the log stream alone (no provider-level trace
  required).

- GitHub Actions CI pipeline (`.github/workflows/`):
  - `test.yml`: build + `go vet` matrix on Go 1.22 / 1.23, unit tests
    with race detector and coverage upload, and `golangci-lint v1.61`
    using the existing `.golangci.yml` ruleset. Triggered on every push
    to `main` and on pull requests.
  - `docs.yml`: regenerates `docs/` via `go generate ./...`
    (tfplugindocs) and fails the run if the worktree drifts. Acts as a
    hard gate against schema changes that forget to refresh the
    Markdown shipped to the Registry. Path-filtered to provider /
    examples / templates / tooling changes.
  - Acceptance tests (`TF_ACC=1`) are deliberately not run in CI — they
    require a live Windows host over WinRM and belong in a separate
    self-hosted runner / lab pipeline.
- `.github/dependabot.yml`: weekly grouped Go-module and
  GitHub-Actions updates. Major bumps on `terraform-plugin-framework`
  and `terraform-plugin-go` are explicitly ignored (manual review
  required because of breaking-change cadence).
- `.github/pull_request_template.md`: enforces a contributor checklist
  covering unit tests, linting, doc regeneration, CHANGELOG entry, and
  TF_ACC validation when applicable.

### Fixed

- **`windows_registry_value.hive`: invalid schema declared both
  `Required: true` and `Computed: true`.** Terraform itself rejected the
  combination at schema validation time
  (`cannot set both Computed and Required`), but the bug had remained
  hidden until tfplugindocs was wired into CI as part of Tier 2/4 — no
  step in the previous workflow ever ran
  `terraform providers schema -json` on the live provider. Fixed by
  removing the spurious `Computed: true`; the `hiveNormalizePlanModifier`
  contract (uppercase normalisation) is preserved unchanged because plan
  modifiers operate on the planned value regardless of `Computed`.

### Changed

- `go.sum` populated for the modules introduced in Tier 2
  (`terraform-plugin-framework-timeouts`, `terraform-plugin-docs`) and
  for `terraform-plugin-testing` (pinned to **v1.10.0** — the last
  release that targets Go 1.21+/1.22 without bumping the project
  toolchain to Go 1.25). The latter was already imported by three
  acceptance-test skeleton files under the `acceptance` build tag but
  had never been reflected in `go.mod`. Without this pin
  `go mod tidy` would resolve to the latest 1.16.x line which requires
  Go 1.25.8 and breaks the entire module graph for current consumers.
- `.github/workflows/docs.yml`: drift detection step is now
  `continue-on-error: true` while the per-resource templates under
  `templates/` are stubs. The schema-validation half of the workflow
  remains hard-blocking — it is what surfaced the
  `windows_registry_value.hive` bug above. See the inline header in
  the workflow for the migration plan.
- `.github/workflows/docs.yml`: pre-installs Terraform 1.9.8 via
  `hashicorp/setup-terraform@v3` so tfplugindocs picks up the binary
  from `PATH` instead of triggering its bundled `hc-install` download
  path, which fails on `terraform-plugin-docs <=v0.20.1` because of an
  expired GPG signing key.

### Security

- **`windows_service` and `windows_scheduled_task`: stop embedding plaintext
  passwords in PowerShell `-EncodedCommand` payloads.** Both resources used to
  render `service_password` / `principal.password` into the script body via
  `psQuote`, which meant the cleartext was visible to anyone with access to
  WinRM trace logs, IIS WMSvc traces, or any host-side `Set-PSDebug` /
  `Start-Transcript` output on the target. The script body is now scrubbed of
  password values: the plaintext is piped over stdin and read by the script
  through `[Console]::In.ReadLine()` (mirrors the existing `ADR-LU-3` pattern
  used by `windows_local_user`). Regression-guard unit tests assert the
  password is absent from the rendered script and present on stdin
  (`TestCreate_PasswordInjectedViaStdin_NotInScriptBody` and the equivalent
  Update / scheduled-task variants). No state-format or schema change; no
  user action required.

### Added

- Per-operation `timeouts {}` block on the four long-running resources —
  `windows_winget_package`, `windows_legacy_package`, `windows_feature` and
  `windows_scheduled_task` — backed by
  `terraform-plugin-framework-timeouts`. Users can now bound the wall-clock
  duration of `Create`, `Update` and `Delete` independently of the
  provider-level WinRM transport timeout. Defaults: 30 minutes for the three
  package/feature resources (large downloads, MSI/MSIX execution,
  AD-Domain-Services with sub-features), 5 minutes for scheduled tasks
  (CRUD via the `ScheduledTasks` PowerShell module is fast). The block is
  Optional+Computed; absent configuration keeps the default. Note: on
  `windows_legacy_package` the new wall-clock budget is layered on top of
  the existing installer-process `timeout_seconds` attribute; both are
  preserved (different scopes, not redundant).

- `tools/tools.go` and `generate.go` to pin and invoke
  `terraform-plugin-docs` (`tfplugindocs`). `make docs` (alias for
  `go generate ./...`) regenerates the registry-rendered documentation
  under `docs/` directly from the live provider schema, including the new
  `timeouts {}` blocks. The `tools` build tag keeps the generator out of
  the production binary.

- `windows_legacy_package` resource: manages the full lifecycle (install /
  update / uninstall) of Windows software distributed as legacy installers —
  Windows Installer `.msi` packages (via `msiexec.exe`) and `.exe` wrappers
  (InstallShield, NSIS, Inno Setup) via `Start-Process` — over WinRM.
  Complements `windows_winget_package` for software not available via winget
  or shipped as a local/internal binary. Source resolution from local
  `source_path` or fetched `source_url` (mutually exclusive, schema-enforced),
  with mandatory checksum verification (`sha256` / `sha1` / `md5`) before
  exec. MSI ProductCode is auto-extracted at Create when `product_id` is
  omitted. Detection reads both 64-bit and `Wow6432Node` Uninstall registry
  hives; EXE installs are located by `display_name_pattern` (wildcard /
  regex against `DisplayName`) or via an explicit `uninstall_command`. Default
  `valid_exit_codes = [0, 3010]` (3010 = soft reboot). In-place updates for
  `valid_exit_codes`, `timeout_seconds`, `log_path`, `environment` (marked
  sensitive — may carry license keys / proxy creds); all other attributes are
  ForceNew. Import supported by ProductCode GUID (MSI) or exact DisplayName
  (EXE). Drift on manual uninstall removes the resource from state and
  triggers re-create on next apply.

- `windows_winget_package` resource: manages the full lifecycle (install /
  update / uninstall) of a Windows software package via the Microsoft Windows
  Package Manager (`winget`) using the `Microsoft.WinGet.Client` PowerShell
  module over WinRM. Supports create, in-place version update, drift detection,
  deletion, and import. Package scope is always `SystemOrUnknown` (machine-level)
  with silent mode enforced and agreements auto-accepted. Covers 7 attributes:
  `package_id` (ForceNew), `source` (default `winget`; ForceNew), `version`
  (optional pinned version; in-place update), `override` (ForceNew; no control
  chars), `id` (composite `<source>:<package_id>`), `installed_version`
  (observed), and `name` (observed). Handles 9 error kinds with typed
  diagnostics: `module_missing`, `already_installed`, `version_not_available`,
  `blocked_by_policy`, `permission_denied`, `source_unreachable` (1 retry),
  `catalog_error`, `resource_in_use` (3× back-off retry), and `unknown`.
  Import format: `<source>:<package_id>` (first-colon split).

- `windows_firewall_rule` data source: reads the observed state of a Windows
  Defender Firewall rule by its stable technical `name` (InstanceID). Mirrors
  the resource schema in read-only form (no plan modifiers, no defaults beyond
  an implicit `policy_store = "PersistentStore"` applied at Read time). Returns
  an explicit error diagnostic when the rule is not found in the target policy
  store. Reuses the resource's `listFromStrings` helper and the
  `*winclient.FirewallRuleError` enrichment path for typed diagnostics.

- `windows_firewall_rule` resource: manages the full lifecycle of a Windows
  Defender Firewall with Advanced Security rule on a remote host via WinRM +
  PowerShell (`NetSecurity` module). Supports create, in-place update, drift
  detection, deletion, and import. Covers all 19 rule attributes including root
  properties (`direction`, `action`, `profile`, `edge_traversal_policy`,
  `group`, `policy_store`) and filter sub-objects (`protocol`, `local_port`,
  `remote_port`, `local_address`, `remote_address`, `program`, `service`,
  `interface_type`) retrieved via the `Get-NetFirewall*Filter` pipeline.
  Enum fields are normalised to canonical English values regardless of host
  locale (InvariantCulture pinning, ADR-FR-5). Empty filter lists are
  normalised to `["Any"]` to prevent permadiff (ADR-FR-6). Cross-field
  validators enforce profile exclusivity (CV-1) and port/protocol compatibility
  (CV-2). `name`, `group`, and `policy_store` are ForceNew. `GroupPolicy` and
  `RSOP` stores are read-only and return an explicit diagnostic. Import ID
  format: `<name>` (PersistentStore assumed) or `<policy_store>/<name>`.
  Requires Local Administrator on the target host.

- `windows_scheduled_task` resource and data source: manages the full lifecycle
  of a Windows Scheduled Task on a remote host via WinRM + PowerShell
  (ScheduledTasks module, Windows Server 2012+ / Windows 8+). Supports create,
  in-place update, drift detection, deletion, and import. Features include:
  recursive task-folder creation and pruning; configurable principal (including
  domain accounts with semantic write-only password and `password_wo_version`
  rotation counter, ADR-ST-3); up to 32 sequential executable actions; up to 48
  triggers of types `Once`, `Daily`, `Weekly`, `AtLogon`, `AtStartup`, and
  `OnEvent` (XML-injection route for OnEvent, ADR-ST-5); full task settings
  block (`New-ScheduledTaskSettingsSet`). Cross-field validators enforce
  password/logon-type mutual exclusion (EC-4/EC-5) and trigger type–field
  compatibility (EC-7). Import ID format: `<TaskPath><TaskName>` (e.g.
  `\MyFolder\MyTask`). Requires Local Administrator on the target host.



- `windows_environment_variable` resource and data source: manages (or reads)
  a single Windows environment variable (`machine` or `user` scope) on a remote
  host via WinRM + PowerShell. Uses the `.NET Microsoft.Win32.Registry` API for
  type-safe `REG_SZ` / `REG_EXPAND_SZ` storage (ADR-EV-1). Broadcasts
  `WM_SETTINGCHANGE` after every mutation so newly started processes inherit the
  change without a reboot; broadcast failure is non-fatal (ADR-EV-2). Reads
  always use `DoNotExpandEnvironmentNames` for stable drift detection with raw
  `%VAR%` tokens (ADR-EV-5). Import ID format: `<scope>:<name>` (e.g.
  `machine:JAVA_HOME`). Scope `machine` requires Local Administrator; `user`
  requires no elevation. The data source returns a Terraform error for
  non-existent variables (no silent empty state).

- Add 7 data sources mirroring resources: `windows_feature`, `windows_hostname`,
  `windows_local_group`, `windows_local_group_member`, `windows_local_user`,
  `windows_registry_value`, and `windows_service`. Each data source is read-only
  (no Create/Update/Delete/ImportState), uses Required or Optional+ExactlyOneOf
  lookup keys, returns all other attributes as Computed, and raises an explicit
  `AddError` diagnostic when the target object is not found (no silent empty
  state). Write-only or input-only attributes (`password`, `service_password`,
  `status`, `restart`, `source`) are intentionally absent. Full schema
  documentation generated in `docs/data-sources/`.

- `windows_registry_value` resource: manages a single named value (or the
  unnamed **Default** value) inside a Windows registry key on a remote host via
  WinRM + PowerShell, using the `.NET Microsoft.Win32.Registry` API directly
  for type-safe, robust access across all seven Windows registry value kinds
  (`REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`, `REG_QWORD`,
  `REG_BINARY`, `REG_NONE`). Missing parent keys are created automatically and
  recursively at Create time; only the targeted value is removed at Delete time.
  `REG_DWORD` and `REG_QWORD` are expressed as decimal strings to avoid uint32
  overflow and `float64` precision loss (ADR-RV-3). `REG_BINARY` and `REG_NONE`
  use lowercase hex without separators (ADR-RV-4). `REG_EXPAND_SZ` reads raw
  `%VAR%` tokens by default (`expand_environment_variables = false`) for stable
  drift detection (ADR-RV-5). The resource ID is a composite
  `HIVE\PATH\NAME`; the Default value (`name = ""`) has a trailing-backslash
  ID. `hive` input is case-insensitive and normalised to uppercase (ADR-RV-6).
  Three-method client interface (`Set`/`Read`/`Delete`) with a type-conflict
  guard at both plan and runtime layers (ADR-RV-7, EC-3). All PowerShell
  parameters are psQuote-escaped; no user data is raw-concatenated into scripts.
  Structured error classification: `type_conflict`, `not_found`,
  `permission_denied`, `invalid_input`, `unknown`. Import supported via
  `terraform import windows_registry_value.<name> 'HIVE\PATH\NAME'`.

- `windows_local_user` resource: manages a Windows local user account (SAM
  database) on a remote host via WinRM and PowerShell
  (`Microsoft.PowerShell.LocalAccounts`, Windows Server 2016 / Windows 10+).
  The Terraform resource ID is the user **SID** (stable across renames);
  changing `name` issues `Rename-LocalUser -SID` in place — no resource
  replacement (ADR-LU-1). Supports `full_name`, `description` (48-char
  Windows limit, EC-8), `enabled`, `password_never_expires`,
  `user_may_not_change_password`, `account_never_expires`, and
  `account_expires` (RFC3339, future-only at Create, EC-13). Password is
  **Sensitive-only** in TPF 1.13.0 (write-only migration path documented for
  TPF ≥ 1.14.0); plaintext injected via stdin — never in
  `-EncodedCommand` payloads or WinRM trace logs (ADR-LU-3). Password
  rotation driven by `password_wo_version` counter (EC-6). Built-in accounts
  (RID 500/501/503/504) protected against deletion with a hard error
  (ADR-LU-2, EC-2). `password_last_set` is read-only and does not drive
  autonomous drift (ADR-LU-4). Import accepts SID (starts with `S-`) or SAM
  name; post-import `password` is null (EC-11). Structured error
  classification: `not_found`, `already_exists`, `builtin_account`,
  `rename_conflict`, `password_policy`, `permission_denied`, `invalid_name`,
  `unknown`. Adds `ResolveLocalUserSID` helper (symmetric to `ResolveGroup`
  in `local_group_helpers.go`) for resolving a SAM name or SID string to a
  canonical `*UserState` — available for future resources that need local
  user identity resolution without duplicating PowerShell logic.

- `windows_local_group_member` resource: non-authoritative single-membership
  management for Windows local groups (companion to `windows_local_group`).
  Each Terraform resource instance represents one `(group, member)` pair;
  out-of-band memberships are left undisturbed (EC-12). Composite resource ID
  is `"<group_sid>/<member_sid>"` — both SIDs are stable across renames.
  Supports all Windows identity formats for `member` (`DOMAIN\user`, UPN,
  local username, direct SID string). Implements three-tier orphaned-AD-SID
  fallback (`Get-LocalGroupMember` → `Win32_GroupUser` WMI → `net localgroup`)
  for groups containing stale AD SIDs (EC-6). BUILTIN groups (`Administrators`,
  `Remote Desktop Users`, etc.) are explicitly supported as primary targets
  (EC-9). Import accepts `"<group>/<member>"` with name or SID on either side.
  Structured error classification: `group_not_found`, `member_already_exists`,
  `member_unresolvable`, `member_not_found`, `permission_denied`, `unknown`.

- `windows_local_group` resource: manages a Windows local group (Local Users
  and Groups) on a remote host via WinRM and PowerShell
  (`Microsoft.PowerShell.LocalAccounts`, Windows Server 2016 / Windows 10+).
  The Terraform resource ID is the group **SID** (stable across renames);
  changing `name` issues `Rename-LocalGroup` in place — no resource
  replacement. Built-in groups (SID prefix `S-1-5-32-*`) are protected against
  deletion with a hard error. Membership management is out of scope (delegated
  to the future `windows_local_group_member` resource). Supports import by
  group name **or** SID (auto-detected by `S-` prefix). Structured error
  classification: `not_found`, `already_exists`, `builtin_group`,
  `permission_denied`, `name_conflict`, `invalid_name`, `unknown`.

- `windows_hostname` resource: manage the NetBIOS computer name of a remote
  Windows host over WinRM via `Rename-Computer`. Renames are asynchronous —
  the resource never reboots on its own and surfaces `current_name`,
  `pending_name` and `reboot_pending` to drive downstream reboot
  orchestration. The Terraform ID is anchored on `MachineGuid` so it
  survives renames and detects machine replacement out-of-band. Supports
  case-insensitive idempotency, NetBIOS validation (length, charset,
  leading/trailing hyphen, purely numeric), `force`, structured error
  classification (`invalid_name`, `permission_denied`, `domain_joined`,
  `unreachable`, `machine_mismatch`, `concurrent_modification`), and
  import by `MachineGuid`. Workgroup machines only in v1; domain-joined
  hosts are rejected. Destroy is a no-op (a Windows host cannot exist
  without a hostname).
- `windows_feature` resource: install/uninstall a Windows Server role or
  feature over WinRM via `Get-/Install-/Uninstall-WindowsFeature`
  (ServerManager). Supports `include_sub_features`,
  `include_management_tools`, offline `source` (SxS/WIM), `restart`,
  drift detection (`install_state`, `installed`), pending-reboot signalling
  (`restart_pending`), import by feature name, and structured error
  classification (not_found, source_missing, dependency_missing,
  unsupported_sku, permission_denied, timeout).
- `windows_service` resource: full lifecycle management of Windows services
  over WinRM (create, read, update, delete, import). Supports start type,
  runtime status control (Running/Stopped/Paused), custom service account
  with write-only password semantics, dependencies, and cross-field
  validation (EC-4, EC-11).
