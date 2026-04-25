# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

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
