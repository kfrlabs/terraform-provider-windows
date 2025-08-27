# terraform-provider-windows

## Overview

`terraform-provider-windows` is a Terraform provider for managing Windows features, registry keys, and registry values remotely via SSH and PowerShell. It enables automation of Windows server configuration directly from your Terraform workflows.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- Go >= 1.18
- Access to a Windows host with SSH and PowerShell enabled

## Documentation

- [Provider Documentation](./docs/index.md)
- [Resource: windows_feature](./docs/resources/windows_feature.md)
- [Resource: windows_registry_key](./docs/resources/windows_registry_key.md)
- [Resource: windows_registry_value](./docs/resources/windows_registry_value.md)
- [Examples](./exemples/main.tf)

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## Version Compatibility

| Provider Version | Terraform Version | Go Version |
|------------------|------------------|------------|
| 1.0.0            | >= 1.0           | >= 1.18    |

## Support

For issues, questions, or feature requests, please open an issue on [GitHub Issues](https://github.com/k9fr4n/terraform-provider-windows/issues).

For commercial support, contact the maintainer directly.

---
