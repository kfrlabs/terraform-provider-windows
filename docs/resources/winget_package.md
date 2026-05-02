---
page_title: "windows_winget_package Resource - terraform-provider-windows"
subcategory: ""
description: |-
  Manages the install / update / uninstall lifecycle of a Windows software package via the Microsoft Windows Package Manager (winget) using the official PowerShell module Microsoft.WinGet.Client over WinRM.
---

# windows_winget_package (Resource)

Manages the install / update / uninstall lifecycle of a Windows software
package via the Microsoft Windows Package Manager (`winget`) using the official
PowerShell module `Microsoft.WinGet.Client` over WinRM.

The module **must** already be installed on the target host before using this
resource. The provider does **not** auto-install it. Install it once with:

```powershell
Install-Module Microsoft.WinGet.Client -Scope AllUsers -Force
```

Install scope is always `SystemOrUnknown` (machine-level), silent mode is
always enforced, and package/source agreements are always auto-accepted.

~> **ForceNew attributes.** Changing `package_id`, `source`, or `override`
destroys and recreates the package (uninstall + reinstall). For production
systems plan maintenance windows accordingly.

~> **Reboot may be required.** Some installers signal a required reboot on
completion. The provider emits a Terraform **warning** diagnostic but does
**not** fail the operation. The host must be rebooted manually or via an
external mechanism.

~> **Elevated session required.** The WinRM session must run as a Local
Administrator. Otherwise the operation fails with a `permission_denied` error.

## Example Usage

### Install latest available version

```terraform
resource "windows_winget_package" "vscode" {
  package_id = "Microsoft.VisualStudioCode"
  source     = "winget"
}
```

### Install a pinned version

```terraform
resource "windows_winget_package" "nodejs" {
  package_id = "OpenJS.NodeJS.LTS"
  source     = "winget"
  version    = "20.11.0"
}
```

### Install with custom installer arguments

```terraform
resource "windows_winget_package" "myapp" {
  package_id = "Contoso.MyApp"
  source     = "winget"
  override   = "/S /ALLUSERS"
}
```

### Microsoft Store package

```terraform
resource "windows_winget_package" "wt" {
  package_id = "9N0DX20HK701"
  source     = "msstore"
}
```

## Schema

### Required

- `package_id` (String) winget catalog identifier (e.g. `Microsoft.VisualStudioCode`). Matched exactly via `-MatchOption Equals`. **Immutable after creation (ForceNew).** Length 1–255. Must start with an alphanumeric character and contain only alphanumeric characters, dots (`.`), underscores (`_`), plus signs (`+`), and hyphens (`-`).

### Optional

- `override` (String) Raw extra arguments forwarded to the underlying installer via `-Override` on `Install-WinGetPackage` (e.g. MSI properties). **Immutable after creation (ForceNew).** Max 4096 characters. Must not contain control characters (U+0000–U+001F, U+007F). **Do not embed secrets here**: this value is logged by winget and stored in Terraform state in plaintext.
- `source` (String) winget source (catalog) name. Defaults to `winget`. Allowed values: `winget`, `msstore`. **Immutable after creation (ForceNew).**
- `version` (String) Pinned package version (e.g. `1.85.2`). When null/absent, the *latest available* version is targeted. When set, a config change triggers `Update-WinGetPackage` in-place (not ForceNew). Length 1–128 when set.

### Read-Only

- `id` (String) Composite Terraform identifier formatted as `<source>:<package_id>` (e.g. `winget:Microsoft.VisualStudioCode`). Set on creation and stable for the resource lifetime.
- `installed_version` (String) Version actually installed on the host (`.InstalledVersion` from `Get-WinGetPackage`). Populated on Create, Read, and Update.
- `name` (String) Human-readable package display name (`.Name` from `Get-WinGetPackage`). Populated on Create, Read, and Update.

## Version Semantics

### Pinned version (`version` set)

- **Create**: installs the exact version specified via `Install-WinGetPackage -Version`.
- **Read**: reads `installed_version` from the host. No drift is reported if `installed_version != version` (e.g. after a manual update); `installed_version` is purely observational.
- **Update**: when `version` changes, `Update-WinGetPackage` is called in-place (no destroy/recreate). Downgrading may fail if the underlying installer does not support it.

### Latest version (`version` not set / null)

- **Create**: installs the latest version available in the catalog.
- **Read/Update**: no drift is generated on `installed_version`. Changing a `ForceNew` attribute or clearing `version` back to null triggers a reinstall cycle.

## Error Reference

| Kind | Terraform diagnostic |
|------|----------------------|
| `module_missing` | `Microsoft.WinGet.Client` is not installed on the target host. |
| `already_installed` | The package is already installed. Use `terraform import`. |
| `version_not_available` | The pinned version does not exist in the catalog (`NoApplicableInstaller` / `InvalidVersion`). |
| `blocked_by_policy` | The source requires interactive authentication or is policy-blocked (common with `msstore`). |
| `permission_denied` | The WinRM session lacks Local Administrator privileges. |
| `source_unreachable` | Network error reaching the winget source (retried once after 5 s). |
| `catalog_error` | The package ID was renamed or removed from the catalog. |
| `resource_in_use` | winget's per-machine mutex is held (retried 3× with 5 s / 15 s / 30 s back-off). |
| `unknown` | Unexpected PowerShell error or WinRM transport failure. |

## Drift Detection

If the package is removed out-of-band (e.g. via `winget uninstall` or the
Windows Apps settings), the next `terraform plan` will show a non-empty diff
and `terraform apply` will reinstall it automatically (EC-3).

## Import

Import a package by `<source>:<package_id>`:

```shell
terraform import windows_winget_package.vscode winget:Microsoft.VisualStudioCode
```

The split is performed on the **first colon only**, so package IDs that
contain colons are handled correctly. After import, `version` and `override`
are set to `null`. Add them to your configuration and run `terraform plan` to
verify no unintended changes.

## Permissions Required

- Local Administrator on the target Windows host (member of `BUILTIN\Administrators`).
- WinRM enabled and reachable; the user must be permitted in the PSSessionConfiguration (default: `Microsoft.PowerShell`).
- `Microsoft.WinGet.Client` PowerShell module installed on the target host (`Scope AllUsers`).
- Network access from the target host to the configured winget source (`winget` or `msstore`).
