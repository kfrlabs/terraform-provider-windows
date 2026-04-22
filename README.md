# terraform-provider-windows

[INFO] A Terraform provider to manage Windows resources over WinRM.

## Requirements

- [Terraform](https://www.terraform.io/downloads) >= 1.5
- [Go](https://go.dev/dl/) >= 1.22 (for building)
- A Windows target with WinRM enabled and reachable from the machine running Terraform

## Building the provider

```bash
git clone https://github.com/ecritel/terraform-provider-windows.git
cd terraform-provider-windows
make build
```

The binary will be installed into `$GOPATH/bin/terraform-provider-windows`.

## Using the provider

```hcl
terraform {
  required_providers {
    windows = {
      source  = "ecritel/windows"
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
```

Credentials can also be supplied via environment variables:

| Variable            | Purpose                  |
| ------------------- | ------------------------ |
| `WINDOWS_HOST`      | Target hostname / IP     |
| `WINDOWS_USERNAME`  | WinRM username           |
| `WINDOWS_PASSWORD`  | WinRM password (secret)  |

[CRITICAL] Never commit credentials to source control. Use a secret manager
(Azure Key Vault, HashiCorp Vault, AWS SSM, CI/CD secret store).

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

## Generated via KDust pipeline

This provider is produced by a multi-agent KDust pipeline. The bootstrap
step (this scaffold) is followed by per-resource generation agents:

- `bootstrap-provider` — scaffolds module layout, provider block, WinRM client
- `provider-orchestrator` — coordinates resource generation agents
- `resource-codegen` — emits one Terraform resource (schema, CRUD, tests)
- `powershell-author` — produces idempotent PowerShell for each CRUD op
- `acc-tests` — generates acceptance tests and fixtures
- `docs-gen` — runs `tfplugindocs` and curates `docs/`

## License

See `LICENSE` (to be added).
