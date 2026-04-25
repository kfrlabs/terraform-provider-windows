# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

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
