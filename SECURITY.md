# Security Policy

## Supported Versions

Only the latest minor release is supported with security fixes.
Earlier minors are not patched; upgrade to the latest minor first.

See [CHANGELOG.md](CHANGELOG.md) for the current release
(Unreleased section at the top).

## Reporting a Vulnerability

Report vulnerabilities **privately only**, via the GitHub
**Security tab** ("Report a vulnerability") for private vulnerability
reporting.

- Do **not** open a public issue for a suspected vulnerability.
- Do not include secrets, credentials, or live host details in the
  report. The maintainer will provide a secure contact channel via
  the private report thread if follow-up material is needed.

## Response Expectations

- Acknowledgement within **3 business days**.
- Fix timeframe depends on severity: critical issues are addressed
  promptly, others ship in an upcoming minor release.

## Scope

The following are in scope for security reports:

- Secret leaks into logs, diagnostics, errors, or provider output.
  Secrets travel to the target on stdin by design (see
  [ADR-0010](adr/ADR-0010-ssh-transport.md)); anything that defeats
  that separation is a vulnerability.
- Host-key verification bypass: anything that weakens or silently
  skips the fail-closed verification described in
  [ADR-0011](adr/ADR-0011-host-key-verification.md).
- PowerShell injection, including quoting defects in `psQuote`.

Reminder: plain (non-`_wo`) secret attributes such as `password`
remain persisted as sensitive values in Terraform state by design.
Prefer the WriteOnly `*_wo` attributes with their `*_wo_version`
counterparts wherever they exist, so secret values never reach
state or plans.
