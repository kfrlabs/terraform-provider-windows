---
page_title: "windows Provider"
subcategory: ""
description: |-
  The windows provider manages Windows resources over SSH (the target host's OpenSSH Server, invoking PowerShell). It supports public-key, ssh-agent and password authentication, and verifies the server's host key by default.
---

# windows Provider

The windows provider manages Windows resources over SSH (the target host's OpenSSH Server, invoking PowerShell). It supports public-key, ssh-agent and password authentication, and verifies the server's host key by default.

## Requirements

Terraform >= 1.11 is required (Write-only arguments require Terraform 1.11 and later).

## Compatibility and requirements

### Target host

| OS | Status |
| --- | --- |
| Windows Server 2025 (`windows-latest` CI runners plus a `windows-2025` lab host) | Supported (tested in 2025) |
| Windows Server 2022 | Smoke-tested weekly (`testacc-compat` lane: OS facts, DISM names, NTP/timezone/service/power reads, registry, file, event log) |
| Windows Server 2019 / 2016, Windows 10 / 11 client SKUs | Best-effort, untested (no 2019 runner available; see `testacc-compat.yml`) |

### PowerShell

The provider opens one persistent PowerShell 7 (`pwsh.exe`) session per SSH
connection and multiplexes operations over it. Hosts without `pwsh.exe` fall
back to one `powershell.exe` process per call (slower, same semantics).
Carve-out: `windows_dsc_resource` requires Windows PowerShell 5.1
(`Invoke-DscResource`, DSC 1.1) and does not support PowerShell 7 / DSCv3.
PowerShell must run in `FullLanguage` mode: WDAC/AppLocker constrained
language mode (`ConstrainedLanguage`, `RestrictedLanguage`, `NoLanguage`) or
a JEA restricted endpoint is unsupported and fails closed (no fallback — the
one-shot transport requires `FullLanguage` too).

### Privileges

Most resources manage machine state and need an administrator connection.
Elevation failures surface generically (typically `permission_denied`); the
join credential for `windows_domain_membership` additionally needs domain
rights to create/move the computer account in the target OU.

### SSH server limits

`max_sessions` (default `4`) stays under the OpenSSH default `MaxSessions 10`.
Servers enforcing stricter `MaxStartups` / `ClientAliveInterval` policies may
need operator-side review; connection-scale behaviour is tracked in #342
(no tuning values are recommended here).

### Reboots

Resources that need a reboot (`windows_feature` and `windows_domain_membership`
with `restart = true`) schedule a detached host reboot ~60s after the operation
completes (`shutdown.exe /r /t 60`), so the reboot lands after Terraform records
state. No reboot is scheduled when the operation does not require one; the pending
flag (`restart_pending` / `pending_reboot`) is set instead and the host must be
rebooted out-of-band.

The reboot is scheduled per-resource: a reboot tears down every in-flight SSH
session on the same host, so when several reboot-requiring resources apply
together a later operation can still be dropped by an earlier reboot. Mitigations:
enable `restart = true` on at most one resource per apply (a single reboot owner),
apply reboot-requiring resources last or separately (for example
`terraform apply -target=<reboot-owner>` followed by a full apply), or order them
with `depends_on` so the reboot owner runs last.

## Example Usage

```terraform
terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.4"
    }
  }
}

# Recommended: public-key authentication, with the server's identity verified
# against the local known_hosts file (the default).
provider "windows" {
  host             = var.windows_host
  username         = var.windows_username
  private_key_path = "~/.ssh/id_ed25519"
}

# In CI or Terraform Cloud there is usually no known_hosts file, so pin the
# server key directly. Obtain it with `ssh-keyscan <host>` and verify the
# fingerprint out of band before trusting it.
provider "windows" {
  alias = "ci"

  host        = var.windows_host
  username    = var.windows_username
  private_key = var.windows_private_key
  host_key    = var.windows_host_key # "ssh-ed25519 AAAAC3Nz..."
}

# Password authentication remains supported, and host verification still
# applies. Prefer keys where the target allows it.
provider "windows" {
  alias = "password"

  host             = var.windows_host
  username         = var.windows_username
  password         = var.windows_password
  known_hosts_path = "/etc/ssh/known_hosts"
}
```

## Authentication

The provider offers every configured credential to the server, in the usual
OpenSSH order:

1. **Public key** — `private_key` (PEM inline) or `private_key_path`. Add
   `private_key_passphrase` when the key is encrypted.
2. **ssh-agent** — used automatically when `SSH_AUTH_SOCK` is set. Force it on
   or off with `use_agent`. On Windows the agent is reached through a named
   pipe rather than a Unix socket, which the provider does not currently dial:
   use `private_key_path` when Terraform itself runs on Windows.
3. **Password** — `password`.

Prefer keys: a password is replayable by whoever observes it, and the target's
OpenSSH Server can be configured to refuse password authentication entirely.

Every connection attribute has an environment fallback (`WINDOWS_HOST`,
`WINDOWS_PORT`, `WINDOWS_USERNAME`, `WINDOWS_PASSWORD`, `WINDOWS_PRIVATE_KEY`,
`WINDOWS_PRIVATE_KEY_PATH`, `WINDOWS_PRIVATE_KEY_PASSPHRASE`,
`WINDOWS_USE_AGENT`, `WINDOWS_KNOWN_HOSTS`, `WINDOWS_HOST_KEY`,
`WINDOWS_INSECURE_IGNORE_HOST_KEY`, `WINDOWS_MAX_SESSIONS`), which keeps secrets out of `.tf` files and
out of Terraform state. Precedence is explicit HCL > set environment variable
> built-in default; a set-but-malformed `WINDOWS_PORT`, `WINDOWS_TIMEOUT`,
`WINDOWS_MAX_SESSIONS`, `WINDOWS_USE_AGENT` or
`WINDOWS_INSECURE_IGNORE_HOST_KEY` is an error rather than a silent fallback.

## Host key verification

The provider verifies the server's host key **by default**. Without it,
authentication proves who you are to the server but nothing about who answered,
so an interposed host could collect your credentials and every PowerShell
payload the provider sends.

Pick one of:

- **`known_hosts_path`** — an OpenSSH `known_hosts` file. Defaults to
  `~/.ssh/known_hosts`. Populate it with
  `ssh-keyscan <host> >> ~/.ssh/known_hosts`.
- **`host_key`** — the expected public key inline, as printed by `ssh-keyscan`
  (`ssh-ed25519 AAAAC3Nz...`). Use this in CI and Terraform Cloud, where no
  `known_hosts` file exists.

If neither is usable the provider **fails closed** rather than connecting
without verification. Verify the fingerprint out of band the first time; after
that, a mismatch is reported as a possible man-in-the-middle rather than a
routine error.

`insecure_ignore_host_key = true` disables verification entirely. It emits a
warning on every plan and apply, and should be reserved for disposable hosts on
a trusted network.

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `host` (String) Hostname or IP address of the target Windows host. May also be set via WINDOWS_HOST.
- `host_key` (String) The server's expected public key in authorized_keys form (e.g. 'ssh-ed25519 AAAAC3Nz...'), pinned directly instead of consulting a known_hosts file. Useful in CI or Terraform Cloud, where no known_hosts exists. Mutually exclusive with known_hosts_path. May also be set via WINDOWS_HOST_KEY.
- `insecure_ignore_host_key` (Boolean) Disable host key verification entirely. This exposes every connection to man-in-the-middle interception and should only be used against disposable hosts on a trusted network. Defaults to false. May also be set via WINDOWS_INSECURE_IGNORE_HOST_KEY. Precedence: explicit HCL > set WINDOWS_INSECURE_IGNORE_HOST_KEY > default false, so an explicit false keeps verification on even when the variable is true. A set-but-malformed variable is an error.
- `known_hosts_path` (String) OpenSSH known_hosts file used to verify the server's host key. Defaults to ~/.ssh/known_hosts. Mutually exclusive with host_key. May also be set via WINDOWS_KNOWN_HOSTS.
- `max_sessions` (Number) Maximum number of concurrent SSH/PowerShell sessions against the target host. Terraform's parallelism is otherwise serialised to 1 by the single-session transport: a slow operation blocks every other resource. Defaults to 4, which stays under the OpenSSH default MaxSessions 10. May also be set via WINDOWS_MAX_SESSIONS. Precedence: explicit HCL > set WINDOWS_MAX_SESSIONS > default 4. A set-but-malformed WINDOWS_MAX_SESSIONS is an error.
- `password` (String, Sensitive) SSH password. May also be set via WINDOWS_PASSWORD. Prefer key-based authentication where possible.
- `port` (Number) SSH port. Defaults to 22. May also be set via WINDOWS_PORT. Precedence: explicit HCL > set WINDOWS_PORT > default 22. A set-but-malformed or out-of-range WINDOWS_PORT is an error.
- `private_key` (String, Sensitive) PEM-encoded SSH private key used for public-key authentication. Mutually exclusive with private_key_path. May also be set via WINDOWS_PRIVATE_KEY.
- `private_key_passphrase` (String, Sensitive) Passphrase decrypting the private key, when it is protected. May also be set via WINDOWS_PRIVATE_KEY_PASSPHRASE.
- `private_key_path` (String) Path to a PEM-encoded SSH private key. A leading '~' is expanded to the current user's home directory. Mutually exclusive with private_key. May also be set via WINDOWS_PRIVATE_KEY_PATH.
- `timeout` (String) Timeout for establishing the SSH connection (TCP dial plus handshake), as a Go duration string (e.g. 30s, 2m). Default: 30s. This does NOT bound how long a PowerShell operation may run: use the per-resource timeouts block for that. May also be set via WINDOWS_TIMEOUT. Precedence: explicit HCL > set WINDOWS_TIMEOUT > default 30s. A set-but-malformed WINDOWS_TIMEOUT is an error.
- `use_agent` (Boolean) Whether to authenticate through the ssh-agent advertised by SSH_AUTH_SOCK. When unset, the agent is used if SSH_AUTH_SOCK is present. Unavailable when Terraform itself runs on Windows, where the agent is a named pipe rather than a Unix socket: use private_key_path there. May also be set via WINDOWS_USE_AGENT. Precedence: explicit HCL > set WINDOWS_USE_AGENT > SSH_AUTH_SOCK default. A set-but-malformed WINDOWS_USE_AGENT is an error.
- `username` (String) SSH username. May also be set via WINDOWS_USERNAME.
