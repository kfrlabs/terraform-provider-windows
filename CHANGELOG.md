# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

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
