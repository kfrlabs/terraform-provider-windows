# terraform-provider-windows

A Terraform provider to manage Windows resources over **SSH**: it connects to
the target host's OpenSSH Server and executes PowerShell there.

## Requirements

- [Terraform](https://www.terraform.io/downloads) >= 1.5
- [Go](https://go.dev/dl/) >= 1.25 (for building; tracks the `go` directive in `go.mod`)
- A Windows target running **OpenSSH Server**, reachable from the machine
  running Terraform, with PowerShell as the SSH login shell

Enabling OpenSSH Server on the target (once, as an administrator):

```powershell
Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
Set-Service -Name sshd -StartupType Automatic
# The provider invokes PowerShell over the SSH session, so make it the default shell.
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
  -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
  -PropertyType String -Force
Start-Service sshd
```

## Building the provider

```bash
git clone https://github.com/kfrlabs/terraform-provider-windows.git
cd terraform-provider-windows
make build
```

The binary will be installed into `$GOPATH/bin/terraform-provider-windows`.

## Using the provider

```hcl
terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host             = var.windows_host
  username         = var.windows_username
  private_key_path = "~/.ssh/id_ed25519"
}
```

### Authentication

Every credential you configure is offered to the server, in the conventional
OpenSSH order: explicit private key, then ssh-agent, then password. At least
one is required.

| Method | Attributes |
| --- | --- |
| Public key | `private_key` (PEM inline, sensitive), `private_key_path`, `private_key_passphrase` |
| ssh-agent | `use_agent` — used automatically when `SSH_AUTH_SOCK` is set |
| Password | `password` |

Prefer keys: a password is replayable by whoever observes it, and the target's
OpenSSH Server can be configured to refuse password authentication outright.

On Windows, ssh-agent is reached through a named pipe rather than a Unix
socket, which this provider does not currently dial — use `private_key_path`
when Terraform itself runs on Windows.

### Host key verification

The provider **verifies the server's host key by default**, and **fails closed**
if it cannot: with neither `host_key` nor a readable `known_hosts` file it
returns an error instead of connecting unverified. Pick one:

- `known_hosts_path` — an OpenSSH `known_hosts` file, defaulting to
  `~/.ssh/known_hosts`. Populate it with `ssh-keyscan <host> >> ~/.ssh/known_hosts`
  after verifying the fingerprint out of band.
- `host_key` — the expected public key inline, as printed by `ssh-keyscan`
  (`ssh-ed25519 AAAAC3Nz...`). Use this in CI and Terraform Cloud, where no
  `known_hosts` file exists.

`insecure_ignore_host_key = true` disables the check entirely. It emits a
warning on every plan and apply, and belongs only on disposable hosts on a
trusted network.

### Environment variables

Every connection attribute has an environment fallback, which keeps secrets out
of `.tf` files and out of Terraform state:

| Variable | Purpose |
| --- | --- |
| `WINDOWS_HOST` | Target hostname / IP |
| `WINDOWS_PORT` | SSH port (default `22`) |
| `WINDOWS_USERNAME` | SSH username |
| `WINDOWS_PASSWORD` | SSH password (secret) |
| `WINDOWS_PRIVATE_KEY` | PEM-encoded private key (secret) |
| `WINDOWS_PRIVATE_KEY_PATH` | Path to a PEM-encoded private key |
| `WINDOWS_PRIVATE_KEY_PASSPHRASE` | Passphrase decrypting that key (secret) |
| `WINDOWS_USE_AGENT` | `true`/`false` to force ssh-agent on or off |
| `WINDOWS_KNOWN_HOSTS` | `known_hosts` file used to verify the host key |
| `WINDOWS_HOST_KEY` | Expected host public key, pinned inline |
| `WINDOWS_INSECURE_IGNORE_HOST_KEY` | `true` to disable host key verification |

Never commit credentials to source control. Use a secret manager (Azure Key
Vault, HashiCorp Vault, AWS SSM, CI/CD secret store).

## Developing the provider

Common development tasks are exposed through the `GNUmakefile`:

| Target      | Purpose                                    |
| ----------- | ------------------------------------------ |
| `build`     | `go install` the provider                  |
| `test`      | Run short unit tests                       |
| `testacc`   | Run acceptance tests (requires `TF_ACC=1`) |
| `lint`      | Run `golangci-lint`                        |
| `fmt`       | Format Go and example Terraform files      |
| `docs`      | Regenerate provider docs via `tfplugindocs`|

`make test` needs no Windows host. It does exercise the SSH transport, against
an in-process server on loopback (`internal/winclient/transport_test.go`), so
authentication and host key verification are covered without a remote target.

## Generated via KDust pipeline

This provider is produced by a multi-agent KDust pipeline. The bootstrap
step (this scaffold) is followed by per-resource generation agents:

- `bootstrap-provider` — scaffolds module layout, provider block, SSH client
- `provider-orchestrator` — coordinates resource generation agents
- `resource-codegen` — emits one Terraform resource (schema, CRUD, tests)
- `powershell-author` — produces idempotent PowerShell for each CRUD op
- `acc-tests` — generates acceptance tests and fixtures
- `docs-gen` — runs `tfplugindocs` and curates `docs/`

## License

See `LICENSE` (to be added).
