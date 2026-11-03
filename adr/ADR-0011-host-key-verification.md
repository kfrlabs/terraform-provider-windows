# ADR-0011 — Verify SSH host keys by default, and fail closed

- Status: Accepted
- Date: 2026-08-25
- Supersedes: none
- Relates to: ADR-0010 (SSH transport), PR #79

## Context

The first SSH implementation (ADR-0010) shipped with
`ssh.InsecureIgnoreHostKey()` on the default path, because it made the
provider work everywhere immediately. That is precisely the trap: nothing
fails, nothing warns, and the connection simply stops proving who answered.

The exposure is not theoretical for this provider. Authentication proves the
*client's* identity to the server. Without host key verification, a host able
to intercept the connection collects, in order: the username, the password if
password auth is in use, and then every PowerShell payload the provider sends —
which includes `windows_local_user` passwords and any other secret passed on
stdin by `RunPowerShellWithInput`. The stdin-secret design exists specifically
to keep plaintext out of the command line and session logs; accepting any host
key hands that same plaintext to whoever answers.

## Decision

Verify the server's host key **by default**, and **fail closed**: when no
trust anchor is available, `winclient.New` returns an error rather than
connecting unverified.

Exactly one of three mechanisms decides how, and they are mutually exclusive:

1. `known_hosts_path` — an OpenSSH `known_hosts` file, defaulting to
   `~/.ssh/known_hosts`.
2. `host_key` — the expected public key pinned inline, in `authorized_keys`
   form. This exists because CI runners and Terraform Cloud have no
   `known_hosts` file, and without it those environments would have no option
   but the insecure opt-out.
3. `insecure_ignore_host_key` — the explicit opt-out. It cannot be combined
   with either of the above, and the provider raises a **warning diagnostic on
   every plan and apply** when it is set.

Both decisions — which credentials to offer, and whether to trust the server —
live in `internal/winclient/auth.go`, kept out of `client.go` so that the two
security-critical choices are in one small, reviewable file.

## Consequences

### This is a breaking change, deliberately

Existing configurations stop connecting until a trust anchor is configured.
That is the intended behaviour: silently downgrading to no verification is the
failure mode we are removing. The upgrade path is one of `ssh-keyscan <host> >>
~/.ssh/known_hosts` (fingerprint verified out of band), setting `host_key`, or
the documented opt-out.

### "Not known" and "key changed" must stay distinct

`explainKnownHostsError` splits `knownhosts.KeyError` into two messages:

- a host absent from `known_hosts`, with the `ssh-keyscan` command to add it;
- a **HOST KEY MISMATCH**, naming man-in-the-middle as the possibility and
  giving `ssh-keygen -R` for the legitimate-rebuild case.

Collapsing these into one error trains operators to clear the entry reflexively,
which is exactly how a real MITM gets waved through. Any change to this file
must preserve the distinction — and must keep key material out of error text;
fingerprints (`ssh.FingerprintSHA256`) only.

### Authentication precedence

`buildAuthMethods` offers every configured credential in the conventional
OpenSSH order — explicit key, then ssh-agent, then password — so a server that
refuses one method can still accept another. `password` is no longer required;
any single method suffices. A broken agent is an error when `use_agent = true`
was explicit, and skipped silently when the agent was merely auto-detected from
`SSH_AUTH_SOCK`: an operator who asked for the agent should hear about it, one
who happened to have a socket exported should not be blocked by it.

### Known limitation: ssh-agent on Windows

`agentAuthMethod` dials a Unix socket. Windows' OpenSSH agent is a named pipe
(`\\.\pipe\openssh-ssh-agent`), so agent auth is unavailable when Terraform
itself runs on Windows; `private_key_path` is the documented alternative. Adding
named-pipe support means a new dependency (`Microsoft/go-winio`) and was
deferred rather than decided against.

### CI

Because the provider now fails closed, the acceptance workflow must establish a
trust anchor before running: `testacc-windows.yml` records the runner's own host
key with `ssh-keyscan` into `WINDOWS_KNOWN_HOSTS`. That is sound **only**
because the target is the same machine, so there is no network path for an
interposed host — the workflow says so in a comment, because the pattern is
otherwise exactly the wrong thing to copy.
