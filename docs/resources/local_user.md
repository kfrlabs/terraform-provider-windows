---
page_title: "windows_local_user Resource - terraform-provider-windows"
subcategory: ""
description: |-
  Manages a Windows local user account (SAM database) on a remote host via WinRM and PowerShell (Microsoft.PowerShell.LocalAccounts, Windows Server 2016 / Windows 10+). The resource ID is the user SID (stable across renames). Passwords are Sensitive and injected via stdin — never logged. Companion to windows_local_group and windows_local_group_member.
---

# windows_local_user (Resource)

Manages a Windows local user account (SAM database) on a remote host via
WinRM and PowerShell (`Microsoft.PowerShell.LocalAccounts` module, built-in
from **Windows Server 2016 / Windows 10 build 1607** onwards).

This resource manages the account **entity itself** — credentials, display
metadata, expiry flags, and enable/disable state. Group membership is
explicitly out of scope and is delegated to
[`windows_local_group_member`](local_group_member.md), completing the
**"local accounts" triptyque** alongside
[`windows_local_group`](local_group.md) and `windows_local_group_member`.

~> **ID anchored on SID.** The Terraform resource ID equals the user's
**Security Identifier** (e.g. `S-1-5-21-…-1001`). The SID is assigned by
Windows at creation time and **does not change when the account is renamed**.
A change to the `name` attribute issues `Rename-LocalUser -SID <sid>` in
place — no resource replacement (ADR-LU-1).

~> **Password handling.** The `password` attribute is `Sensitive`. The
plaintext is injected via **stdin** inside the PowerShell script and **never
appears in WinRM trace logs, `-EncodedCommand` payloads, or provider
diagnostics** (ADR-LU-3). Use `password_wo_version` to trigger forced
rotation without changing the password value. Write-only semantics
(TPF ≥ 1.14.0 + Terraform CLI ≥ 1.11) will replace the Sensitive attribute
in a future minor version once the framework support is stable.

~> **Built-in account protection.** Attempting `terraform destroy` on a
built-in account (RID 500 `Administrator`, 501 `Guest`, 503
`DefaultAccount`, 504 `WDAGUtilityAccount`) results in a **hard error**.
Use `terraform state rm` to remove such resources from state without
deleting the underlying account.

~> **Local accounts only.** This resource manages Windows **local** accounts
via `Microsoft.PowerShell.LocalAccounts`. Domain accounts in Active Directory
are **not** manageable through this resource. Domain-joined machines are
fully supported for *local* account management.

## Example Usage

### Minimal — create a local service account

```terraform
resource "windows_local_user" "svc_backup" {
  name     = "svc-backup"
  password = var.svc_backup_password
}
```

### Full provider block + custom user

```terraform
terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
}

# Create a local service account that never expires.
resource "windows_local_user" "svc_backup" {
  name                         = "svc-backup"
  full_name                    = "Backup Service Account"
  description                  = "Runs the nightly backup job."
  password                     = var.svc_backup_password
  password_wo_version          = 1
  enabled                      = true
  password_never_expires       = true
  user_may_not_change_password = true
  account_never_expires        = true
}

output "svc_backup_sid" {
  value       = windows_local_user.svc_backup.sid
  description = "SID of svc-backup — stable across renames."
}
```

### Account with expiry date

```terraform
resource "windows_local_user" "temp_contractor" {
  name                  = "temp-contractor"
  full_name             = "Contractor Access"
  description           = "Temporary contractor — expires 2027-12-31."
  password              = var.contractor_password
  password_wo_version   = 1
  account_never_expires = false
  account_expires       = "2027-12-31T23:59:59Z"
}
```

### Full triptyque — user + group + membership

```terraform
variable "svc_password" {
  type      = string
  sensitive = true
}

# 1. Local user account
resource "windows_local_user" "svc_app" {
  name                         = "svc-app"
  full_name                    = "App Service Account"
  description                  = "Runs the AppSuite service."
  password                     = var.svc_password
  password_wo_version          = 1
  enabled                      = true
  password_never_expires       = true
  user_may_not_change_password = true
  account_never_expires        = true
}

# 2. Custom local group
resource "windows_local_group" "app_operators" {
  name        = "AppOperators"
  description = "Operators allowed to run AppSuite."
}

# 3. Grant svc-app membership in AppOperators
resource "windows_local_group_member" "app_operators_svc" {
  group  = windows_local_group.app_operators.name
  member = windows_local_user.svc_app.name
}
```

### In-place rename (no resource replacement)

```terraform
# Rename svc-backup to svc-bkp: issues Rename-LocalUser -SID <sid>.
# The SID (and Terraform resource ID) remain unchanged.
resource "windows_local_user" "svc_backup" {
  name     = "svc-bkp"
  password = var.svc_backup_password
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `name` (String) SAM account name of the local user (e.g. `svc-backup`, `jdoe`).

  Constraints (EC-10, ADR-LU-5):
  - Length: 1..20 characters (Windows SAM hard limit)
  - Forbidden characters: `/` `\` `[` `]` `:` `;` `|` `=` `,` `+` `*` `?` `<` `>` `"`
  - Must not consist solely of whitespace characters
  - Must not start or end with a space

  **In-place rename:** a change issues `Rename-LocalUser -SID <sid> -NewName <name>` —
  no resource replacement (ADR-LU-1, EC-5).

  **Case normalisation:** Windows casing wins in state; case-only differences
  do not trigger spurious renames (EC-4).

### Optional

- `password` (String, Sensitive) Password for the account. Must satisfy the local password
  policy (minimum length, complexity). Required at Create; if omitted the provider raises
  a diagnostic error before calling `New-LocalUser`.

  The plaintext is injected via **stdin** inside the PowerShell script and **never appears
  in WinRM trace logs or provider diagnostics** (ADR-LU-3, EC-6).

  After `terraform import`, this attribute is `null`. Set it in HCL before the next apply.
  A future minor version will replace this attribute with a native write-only attribute
  once TPF ≥ 1.14.0 write-only support is stable (migration path: rename attribute, no
  state migration needed).

- `password_wo_version` (Number) Monotonically increasing version counter for password
  rotation (EC-6). When this value changes between plan and apply, the provider calls
  `Set-LocalUser -Password` regardless of whether the `password` value itself changed.
  Conventionally starts at `1`. Must be a positive integer if set.

- `full_name` (String) Display name of the user (`-FullName`). Optional; defaults to `""`.
  Updated in place via `Set-LocalUser -FullName`.

- `description` (String) Free-text description of the account.

  ~> **48-character limit:** Windows hard-limits `LocalUser` descriptions to **48 characters**
  (EC-8, ADR-LU-9). This differs from `windows_local_group` which allows 256 characters.
  The schema enforces this limit at plan time.

- `enabled` (Boolean) Whether the account is active (`true`, default) or disabled (`false`).
  Controlled via `Enable-LocalUser` / `Disable-LocalUser`. Defaults to `true`.

- `password_never_expires` (Boolean) When `true`, the account password never expires
  regardless of the local password policy. Maps to `-PasswordNeverExpires`. Defaults to `false`.

- `user_may_not_change_password` (Boolean) When `true`, the user is prevented from changing
  their own password. Maps to `-UserMayNotChangePassword` (double-negative Windows semantics:
  `true` = cannot change, `false` = can change). Defaults to `false`.

- `account_never_expires` (Boolean) When `true` (default), the account never expires
  (`-AccountNeverExpires`). When `false`, the account expires at `account_expires`.
  Mutually exclusive with `account_expires` when `true` (EC-14, ADR-LU-8). Defaults to `true`.

- `account_expires` (String) RFC3339 timestamp at which the account expires
  (e.g. `"2027-12-31T23:59:59Z"`). When set, `account_never_expires` must be `false`.
  Must be in the future at **Create** time (EC-13). At Update time, past values are
  forwarded to Windows without blocking.

### Read-Only

- `id` (String) Terraform resource ID. Equal to `sid` (the user Security Identifier).
  **Stable across renames**: renaming the account via the `name` attribute does not
  change the resource ID (ADR-LU-1).

- `sid` (String) Security Identifier of the user account (e.g. `S-1-5-21-…-1001`).
  Assigned by Windows when `New-LocalUser` completes. Stable across renames.
  Used as the canonical Terraform resource ID.

- `last_logon` (String) RFC3339 timestamp of the last successful logon, or `""` if the
  account has never been used. Informational only; changes on this attribute do not
  trigger an Update cycle.

- `password_last_set` (String) RFC3339 timestamp of the last provider-initiated password
  change, or `""` if not yet set. Refreshed after `SetPassword` is called. Does **not**
  drive autonomous Update cycles — it is an observation, not a desired-state attribute
  (ADR-LU-4).

- `principal_source` (String) Origin of the account as reported by Windows (`"Local"` for
  local accounts). Exposed for consistency with `windows_local_group_member`.

## Error Classification

Errors are classified into stable kinds, surfaced in the diagnostic detail under `Kind:`:

| Kind                | Typical cause                                                                                          |
|---------------------|--------------------------------------------------------------------------------------------------------|
| `not_found`         | Account disappeared outside Terraform (drift, EC-3) or import target does not exist (EC-11).          |
| `already_exists`    | An account with the same name already exists at Create time; use `terraform import` (EC-1).            |
| `builtin_account`   | Attempt to destroy a built-in account (RID 500/501/503/504, EC-2).                                    |
| `rename_conflict`   | The rename target name is already used by another local account (EC-5).                                |
| `password_policy`   | The password violates the local password policy (minimum length, complexity, EC-7).                   |
| `permission_denied` | The WinRM user lacks Local Administrator rights on the target host (EC-9).                             |
| `invalid_name`      | Windows-side name validation failure — defence-in-depth after schema validators (EC-10).              |
| `unknown`           | Catch-all for unexpected PowerShell or WinRM transport failures.                                       |

## Notes

### Password handling and write-only migration path

`password` is stored as a `Sensitive` string in Terraform state (encrypted at
rest in the state backend). The plaintext is **never** interpolated into the
PowerShell `-EncodedCommand` body: it is injected via stdin and read by the
script via `[Console]::In.ReadLine()`, preventing leakage into WinRM trace
logs. When TPF ≥ 1.14.0 write-only support becomes stable, the attribute will
be migrated to a native write-only field — no state migration is required as
the attribute name will remain `password`.

### Built-in account protection

Built-in accounts (RID 500 `Administrator`, 501 `Guest`, 503 `DefaultAccount`,
504 `WDAGUtilityAccount`) can be **managed** (renamed, enabled/disabled,
description updated) through this resource but **never destroyed**. The guard
is SID-RID-based and immune to renames. To stop managing a built-in account
without deleting it, use `terraform state rm`.

### In-place rename safety

`Rename-LocalUser -SID <sid>` is always called **before** `Set-LocalUser` in
the same Update step (ADR-LU-6), ensuring the SID remains the stable anchor.
A rename that collides with an existing name surfaces a `rename_conflict` error.

### `password_last_set` does not cause drift

`password_last_set` is a read-only observation computed by Windows. It is
refreshed in state after a provider-initiated password rotation, but a change
in its value (e.g. a user-initiated password change out-of-band) does **not**
trigger a Terraform plan diff. Desired-state management of password rotation
is controlled exclusively by `password_wo_version` (ADR-LU-4).

## Permissions

- **Local Administrator** on the target Windows host (required for `New-`,
  `Set-`, `Rename-`, `Enable-`, `Disable-`, `Remove-LocalUser`).
- Standard authenticated WinRM user is sufficient for `Get-LocalUser`
  (read-only operations).
- WinRM enabled and reachable from the Terraform runner:
  - HTTP: TCP 5985
  - HTTPS: TCP 5986
- Windows Server 2016 / Windows 10 build 1607 minimum
  (`Microsoft.PowerShell.LocalAccounts` is built-in from these versions).

## Import

A `windows_local_user` resource can be imported using **either the user SID
or the SAM account name** (EC-11, ADR-LU-6). The import ID is auto-detected:

- If the value **starts with `S-`** → treated as a SID (`Get-LocalUser -SID <value>`).
- Otherwise → treated as a SAM name (`Get-LocalUser -Name <value>`).

After import, the resource ID is always set to the user **SID** regardless of
which import path was used. The `password` attribute will be `null` after
import — set it in HCL and run `terraform apply` before the next plan cycle
(EC-11).

### Import by SID

```shell
terraform import windows_local_user.svc_backup S-1-5-21-1234567890-987654321-1122334455-1001
```

### Import by SAM name

```shell
terraform import windows_local_user.svc_backup svc-backup
```

Retrieve the SID of an account on the target host with:

```powershell
# By name
(Get-LocalUser -Name "svc-backup").SID.Value

# List all local users with SIDs
Get-LocalUser | Select-Object Name, SID, Enabled
```
