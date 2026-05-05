---
page_title: "windows_legacy_package Resource - terraform-provider-windows"
subcategory: ""
description: |-
  Installs, updates and uninstalls Windows software distributed as legacy installers (.msi via msiexec; .exe via Start-Process) over WinRM. Complements windows_winget_package for software not available via winget or shipped as a local/internal binary.
---

# windows_legacy_package (Resource)

Installs, updates and uninstalls Windows software distributed as **legacy
installers** — Windows Installer `.msi` packages and `.exe` wrappers (e.g.
InstallShield, NSIS, Inno Setup). Complements
[`windows_winget_package`](winget_package.md) for software not available via
winget or shipped as a local/internal binary.

Detection is performed against the standard Uninstall registry hives
(`HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` and the
`Wow6432Node` 32-bit view).

~> **Most attributes are ForceNew.** Only `valid_exit_codes`,
`timeout_seconds`, `log_path` and `environment` can be updated in place
(they only affect future invocations). Any other change destroys and
re-creates the package (uninstall + reinstall).

~> **Elevated session required.** The WinRM session must run as a Local
Administrator. `msiexec`, registry write under `HKLM`, and `$env:TEMP`
staging all require it.

~> **Source is mutually exclusive.** Exactly one of `source_path` or
`source_url` must be set. The schema rejects configurations with both or
neither at plan time.

~> **EXE detection.** When `installer_type = "exe"`, at least one of
`display_name_pattern` or `uninstall_command` must be set — the provider
needs a way to locate the install in the Uninstall registry hive (or an
explicit uninstall command) for Read and Delete.

## Example Usage

### MSI from a local path on the target host

```terraform
resource "windows_legacy_package" "sevenzip" {
  name           = "7zip"
  installer_type = "msi"
  source_path    = "C:\\Packages\\7z2407-x64.msi"
  checksum       = "sha256:b099a25b8b4c9e0d6f2e4f3c2c0a3b6d5d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80"
}
```

### MSI fetched from an internal HTTPS URL

```terraform
resource "windows_legacy_package" "npp" {
  name           = "notepadpp"
  installer_type = "msi"
  source_url     = "https://artifacts.internal.example/npp/8.6.4.msi"
  checksum       = "sha256:1a2b3c4d5e6f7081928374655463728190a1b2c3d4e5f60718293a4b5c6d7e8f"
  valid_exit_codes = [0, 3010]
  timeout_seconds  = 1800
}
```

### EXE installer (NSIS) located by display name

```terraform
resource "windows_legacy_package" "vlc" {
  name                 = "vlc"
  installer_type       = "exe"
  source_url           = "https://artifacts.internal.example/vlc/vlc-3.0.20-win64.exe"
  checksum             = "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
  install_args         = ["/S"]
  uninstall_args       = ["/S"]
  display_name_pattern = "VLC media player*"
}
```

### EXE with explicit uninstall command and custom environment

```terraform
resource "windows_legacy_package" "vendor_tool" {
  name              = "vendor-tool"
  installer_type    = "exe"
  source_path       = "C:\\Packages\\vendor-tool-2.4.0.exe"
  install_args      = ["/quiet", "/norestart"]
  uninstall_command = "C:\\Program Files\\Vendor\\Tool\\uninstall.exe"
  uninstall_args    = ["/silent"]
  valid_exit_codes  = [0, 1641, 3010]
  timeout_seconds   = 3600

  environment = {
    LICENSE_KEY = var.vendor_license_key
    HTTP_PROXY  = "http://proxy.internal:3128"
  }
}
```

## Schema

### Required

- `name` (String) Logical Terraform identifier and display label for the package. Must match `^[A-Za-z0-9._-]{1,128}$`. **Immutable (ForceNew).**
- `installer_type` (String) Installer engine. `msi` uses `msiexec.exe`; `exe` runs the binary directly via `Start-Process`. Allowed values: `msi`, `exe`. **Immutable (ForceNew).**

### Optional

- `source_path` (String) Local path on the target Windows host to the `.msi`/`.exe` file. Mutually exclusive with `source_url`. Must be an absolute Windows path (e.g. `C:\path\to\file.msi`). **Immutable (ForceNew).**
- `source_url` (String) HTTP/HTTPS URL fetched on the target host into `$env:TEMP` before exec. Mutually exclusive with `source_path`. **Immutable (ForceNew).**
- `checksum` (String) Expected installer checksum, format `<algo>:<hex>` where `<algo>` is `sha256`, `sha1`, or `md5`. Verified before exec. Strongly recommended for `source_url`. **Immutable (ForceNew).**
- `insecure_skip_verify` (Bool) Disable TLS certificate validation when fetching `source_url`. **Not recommended** — use only for internal CAs whose root cannot be installed on the host. **Immutable (ForceNew).**
- `product_id` (String) MSI **ProductCode** GUID (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`). Auto-extracted from the MSI at Create when omitted. Computed when not set. **Immutable (ForceNew).**
- `display_name_pattern` (String) Wildcard/regex matched against `DisplayName` under `HKLM:\SOFTWARE\...\Uninstall\*` (and `Wow6432Node`) to locate EXE installs. Required for `installer_type="exe"` when `uninstall_command` is empty. **Immutable (ForceNew).**
- `install_args` (List of String) Extra arguments to the installer. MSI defaults are injected by the provider (`/i`, `/qn`, `/norestart`, `/l*v <log>`); EXE has no defaults. **Immutable (ForceNew).**
- `uninstall_args` (List of String) Extra arguments for uninstallation. MSI default is `["/x", <product_id>, "/qn", "/norestart"]`; appended to `UninstallString` for EXE. **Immutable (ForceNew).**
- `uninstall_command` (String) Explicit EXE uninstall command when the registry `UninstallString` is unreliable or absent. **Immutable (ForceNew).**
- `valid_exit_codes` (List of Number) Exit codes treated as success. Default `[0, 3010]` (3010 = soft reboot pending, common with MSI). **Updatable in place** — only affects future invocations.
- `working_directory` (String) Working directory for the installer process. Defaults to the parent directory of the resolved installer. **Immutable (ForceNew).**
- `timeout_seconds` (Number) Hard timeout (seconds) for install/uninstall. Default `1800`. Range `1`–`86400`. **Updatable in place.**
- `log_path` (String) Path to MSI `/l*v` log or EXE stdout/stderr capture. Auto-generated under `$env:TEMP\windows_legacy_package\` when omitted. Computed when not set. **Updatable in place.**
- `environment` (Map of String, Sensitive) Extra environment variables injected into the installer process. May carry license keys / proxy credentials — **marked sensitive**. **Updatable in place.**

### Read-Only

- `id` (String) Terraform ID. **ProductCode GUID** for MSI; resolved exact `DisplayName` for EXE.
- `installed` (Boolean) Whether the package is currently detected on the host.
- `installed_version` (String) `DisplayVersion` read from the Uninstall registry (or MSI properties) post-install.
- `install_date` (String) `InstallDate` from the Uninstall registry, normalized to ISO-8601 when parseable.

## Update Semantics

| Attribute changed | Effect |
|-------------------|--------|
| `valid_exit_codes`, `timeout_seconds`, `log_path`, `environment` | **In-place** — state-only, applies to next install/uninstall invocation. |
| Any other attribute | **ForceNew** — destroy (uninstall) + create (reinstall). |

## Drift Detection

On every `terraform plan`, the provider re-reads the Uninstall registry hives
(both 64-bit and `Wow6432Node`) and refreshes `installed`, `installed_version`,
and `install_date`. If the entry is gone (manual uninstall via Add/Remove
Programs, registry tampering, image rebuild), the resource is removed from
state and Terraform schedules a re-create on the next apply.

## Exit Codes

Default `valid_exit_codes = [0, 3010]`:

- `0` — success
- `3010` — success, **reboot required**. The provider does not reboot; do it
  out of band.

Common failures surfaced verbatim from `msiexec` / the EXE installer:

- `1618` — another installation in progress (Windows Installer mutex held).
  Not retried automatically; surface clearly so the user can re-apply.
- `1641` — success, reboot initiated. Add to `valid_exit_codes` to whitelist.
- `1602` — user cancel. Should not occur in `/qn` silent mode but is
  reported by some EXE wrappers.

## Security Notes

- Always set `checksum` when using `source_url`. The provider will refuse to
  execute an installer whose hash does not match.
- `insecure_skip_verify = true` disables TLS validation for the download
  step **only**. Avoid it in production; install your internal CA root on
  the target host instead.
- For `source_url`, the provider currently negotiates TLS 1.0/1.1/1.2 to
  remain compatible with legacy artifact servers. Prefer hosts supporting
  TLS 1.2+ exclusively.
- `environment` is marked sensitive — values do not appear in plan output
  but **are persisted in Terraform state**. Use a remote state backend with
  encryption at rest.

## Import

Import an MSI by its **ProductCode GUID** (case-insensitive, braces required):

```shell
terraform import windows_legacy_package.npp '{12345678-1234-1234-1234-1234567890AB}'
```

Import an EXE install by its exact **DisplayName** (case-sensitive, as it
appears under HKLM Uninstall):

```shell
terraform import windows_legacy_package.vlc 'VLC media player'
```

After import, the configuration-only attributes (`source_path`, `source_url`,
`checksum`, `install_args`, ...) are unset in state. Reconcile them with your
config and run `terraform plan` to verify no unintended drift.

## Permissions Required

- Local Administrator on the target Windows host (member of `BUILTIN\Administrators`).
- WinRM listener reachable (HTTP 5985 or HTTPS 5986).
- Outbound HTTP/HTTPS from the target host to `source_url` when used.
- Write access to `$env:TEMP` for download staging and log files.
