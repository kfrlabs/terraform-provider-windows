# ADR-0010 — SSH as the transport to Windows hosts

- Status: Accepted
- Date: 2026-08-25
- Amended: 2026-08-28 (persistent PowerShell session, issue #81)
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

### One persistent session per Client (amended 2026-08-28, issue #81)

Originally `RunPowerShell` dialled a fresh SSH connection and started a fresh
`powershell.exe` for every call. That was simple and stateless, but it meant
paying every call's module-import cost from scratch — `windows_feature`'s
`ServerManager` import alone is ~18s cold — which made a single acceptance
test file take 105-246s for what should be a handful of PowerShell round
trips.

`Client` now keeps at most **one** persistent `powershell.exe` session open
(`internal/winclient/session.go`), reused across every `RunPowerShell` /
`RunPowerShellWithInput` call for that `Client`'s lifetime:

- The bootstrap (`psReplBootstrap`) is a loop, not a one-shot script: it reads
  successive requests from stdin — two base64 lines, script then secret input
  — and frames each response with a sentinel line
  (`##WINCLIENT-END:<status>##` / `##WINCLIENT-END##`) so the client can tell
  where one call's output ends and the next begins. The command line stays
  fixed regardless of call count, preserving the #39 guarantee.
- The secret is bound to the call via `[Console]::SetIn` over a `MemoryStream`
  scoped to exactly the decoded secret bytes, so existing scripts'
  `[Console]::In.ReadLine()` / `ReadToEnd()` calls are unmodified: `ReadToEnd()`
  hits the end of that stream, not the outer pipe, so it never blocks waiting
  for the next request.
- Calls are serialised by `Client.mu`: the session's stdin/stdout/stderr is one
  shared, ordered stream, so two calls cannot safely interleave on it. A single
  session (rather than a pool) was chosen deliberately for the first
  iteration — it is far simpler to reason about and test, and the actual cost
  being eliminated (module import) dwarfs the cost of serialising calls that
  were largely sequential per resource anyway. A pool is a candidate follow-up
  if concurrent-apply throughput turns out to matter in practice.
- A session that turns out to be dead (dropped connection, crashed remote
  process) is transparently closed and re-established once before the call is
  retried, so a stale session does not permanently fail every subsequent call.
- `exit` inside a script now terminates the whole reusable `powershell.exe`
  process, not just that call — the opposite of what the old one-process-per-call
  model relied on for early-return-after-`Emit-Err`. Existing scripts that used
  `exit 0` this way are being migrated to return a status the caller checks
  (e.g. `windows_feature`'s `Ensure-FeatureCmdlets` returns `$false` and its
  callers guard with `if (Ensure-FeatureCmdlets) { ... }`) instead of exiting.
  This lands incrementally, resource by resource, validated by the real
  Windows `testacc-windows` CI job each time, starting with `windows_feature`.

`internal/winclient/sshtest_test.go`'s in-process server was extended to speak
this framing protocol (ready handshake, framed per-request response,
`dropAfterCalls` to simulate a session dying mid-use) so session reuse,
concurrent-call serialisation and recovery are covered by the default
`make test`, with no Windows host required.

### Testability, which WinRM never gave us

`x/crypto/ssh` has a server side, so the transport can be driven end to end
against an in-process server on loopback (`internal/winclient/sshtest_test.go`,
`transport_test.go`): auth method selection, host key acceptance and rejection,
and the encoded-command bootstrap are covered in milliseconds, with no Docker,
no network and no Windows host. These run in the default `make test`. The WinRM
client had no equivalent and those paths were only ever exercised by hand.
