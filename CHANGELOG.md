# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

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
