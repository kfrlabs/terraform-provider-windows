# ADR-0010 — SSH as the transport to Windows hosts

- Status: Accepted
- Date: 2026-08-25
- Supersedes: none (records the transport implicitly chosen at bootstrap)
- Relates to: ADR-0011 (host key verification), PR #78

## Context

Until PR #78 the provider reached its targets over **WinRM**, via
`masterzen/winrm`. That choice was inherited from the bootstrap scaffold rather
than decided, and it cost us on four fronts:

- **Setup burden.** WinRM has to be enabled and configured on every target
  (listener, HTTPS certificate or unencrypted HTTP, TrustedHosts, allocated
  memory quotas). None of it is on by default in a way that is safe.
- **Authentication.** Usable auth meant NTLM or Kerberos, which dragged in a
  transitive dependency surface we did not want to audit, and made anything
  other than a password awkward. Key-based authentication was not on the table.
- **Encryption story.** `use_https = false` with NTLM message-level encryption
  is the common deployment, and explaining what is actually protected — and
  what is not — was a recurring source of operator confusion.
- **Direction of travel.** Microsoft ships OpenSSH Server as a Windows
  capability, PowerShell Remoting over SSH is supported, and SSH is what
  operators already have tooling, key management and audit trails for.

## Decision

Connect over **SSH** using `golang.org/x/crypto/ssh`, against the target's
OpenSSH Server, invoking `powershell.exe` as the command. `masterzen/winrm` and
its NTLM/Kerberos dependencies are dropped.

The `winclient` public surface is deliberately unchanged: `RunPowerShell`,
`RunPowerShellWithInput`, and the `-EncodedCommand` + UTF-16LE-on-stdin
bootstrap all keep their semantics, so **no resource or data source changed**.
The transport swap is confined to `client.go` plus the new `auth.go`.

## Consequences

### Breaking changes

- `port` now defaults to `22` (was `5985`/`5986`).
- The `use_https` and `auth_type` provider attributes are **removed**. A
  configuration that sets them fails to plan.
- Targets need OpenSSH Server installed and enabled, with PowerShell as the SSH
  login shell (`HKLM:\SOFTWARE\OpenSSH` → `DefaultShell`). Without that last
  part the bootstrap command is handed to `cmd.exe` and fails.

### Provider `timeout` no longer means what it did

`timeout` feeds `net.Dialer.Timeout` and `ssh.ClientConfig.Timeout` only: it
bounds **connection establishment**, not command execution. Long operations are
bounded by the request `context`, i.e. the per-resource `timeouts {}` block
(30m for `windows_feature`, `windows_legacy_package`, `windows_winget_package`;
5m for `windows_scheduled_task`). Raising `timeout` to accommodate a slow
install does nothing, which is why its description says so explicitly.

### One connection per call

`RunPowerShell` dials a fresh SSH connection every time; there is no session
reuse or multiplexing. This keeps the client stateless and safe to share across
concurrent resource operations, at the cost of a handshake per PowerShell call.
Revisit only if handshake latency shows up in real applies.

### Testability, which WinRM never gave us

`x/crypto/ssh` has a server side, so the transport can be driven end to end
against an in-process server on loopback (`internal/winclient/sshtest_test.go`,
`transport_test.go`): auth method selection, host key acceptance and rejection,
and the encoded-command bootstrap are covered in milliseconds, with no Docker,
no network and no Windows host. These run in the default `make test`. The WinRM
client had no equivalent and those paths were only ever exercised by hand.
