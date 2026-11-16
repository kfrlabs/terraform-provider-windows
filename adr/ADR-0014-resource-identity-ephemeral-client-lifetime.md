# ADR-0014 — Resource identity, ephemeral resources, SSH client lifetime (evaluation)

- Status: Accepted (evaluation only — no adoption code)
- Date: 2026-11-16
- Supersedes: none
- Relates to: issue #403; ADR-0010 (SSH transport); ADR-0012 (partial-failure contract); ADR-0013 (winclient conventions)

## Context

Issue #403 asks whether the provider should adopt three framework
capabilities: resource identity (`ResourceWithIdentity`), ephemeral
resources, and an explicit SSH client lifetime. This record evaluates all
three and adopts none in code: the verdict is pilot-only for identity,
rejected for ephemeral, and intentionally-unchanged for the client
lifetime.

## Decision

### 1. Identity: ADOPT, pilot-only in a follow-up

A follow-up (not this record) may pilot `ResourceWithIdentity` on three
resources: `windows_service` (identity: `name`), `windows_directory`
(identity: absolute path), `windows_registry_key` (identity: hive +
path). Identity values come from the Read canonical form — HKLM in
short form, path as stored — never from raw config.

- The legacy string-ID `ImportState` stays for all ~34 resources.
  Identity sits alongside it, not instead of it. `list`/`query` are out
  of scope.
- Terraform minimum correction: implementing `ResourceWithIdentity`
  must NOT raise the README minimum by itself. Hosts below 1.12 ignore
  identity; only import-by-identity needs 1.12. The pilot must verify a
  plain plan/apply on Terraform 1.11, else it is rejected.
- Framework support is already present: `go.mod` pins
  `terraform-plugin-framework v1.19.0`, which carries identity. No
  dependency bump is needed for the pilot.

### 2. Ephemeral resources: REJECTED

Ephemeral resources are rejected. `WriteOnly: true` plus `*_wo_version`
already covers every secret this provider consumes, and those values
can come from ephemeral sources defined elsewhere (`random_password`,
Vault). An ephemeral resource only makes sense when the Windows host is
the secret source; no such flow exists.

- Future candidate: a LAPS password read would qualify.
- Revisit trigger: the first flow where the Windows host originates a
  secret the configuration must consume ephemerally.

### 3. SSH client lifetime: intentionally never closed

The `*winclient.Client` built in `Configure` (`internal/provider/provider.go`,
above `winclient.New`) is intentionally never closed. The framework
offers no shutdown hook; `New` does not dial until the first
`RunPowerShell` call; `Close` only drains the idle pool plus the agent
connection; process exit reclaims TCP. Adding a close path would break
the shared pooled client. The `Configure` and `winclient.Client.Close`
comments record this (see ADR-0014 pointer there).

## Consequences

- No schema or transport change in this record: `grep` stays empty for
  `ResourceWithIdentity`/`IdentitySchema` and `EphemeralResource` under
  `internal/`.
- README stays at Terraform >= 1.11; `docs/` stays generated and
  untouched; this record lives in `adr/` outside the drift gate.
- The identity pilot, if taken up, verifies plain plan/apply on
  Terraform 1.11 and keeps legacy string-ID import everywhere.
