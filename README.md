# terraform-provider-windows

## Overview

`terraform-provider-windows` is a Terraform provider for managing Windows features, registry keys, registry values, local users, local groups, services, and hostname configuration remotely via SSH and PowerShell. It enables automation of Windows server configuration directly from your Terraform workflows.

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- Go >= 1.18
- Access to a Windows host with SSH and PowerShell enabled

## Documentation

- [Provider Documentation](./docs/index.md)

### Resources

- [Resource: windows_feature](./docs/resources/windows_feature.md)
- [Resource: windows_hostname](./docs/resources/windows_hostname.md)
- [Resource: windows_localuser](./docs/resources/windows_localuser.md)
- [Resource: windows_localgroup](./docs/resources/windows_localgroup.md)
- [Resource: windows_registry_key](./docs/resources/windows_registry_key.md)
- [Resource: windows_registry_value](./docs/resources/windows_registry_value.md)
- [Resource: windows_service](./docs/resources/windows_service.md)

### Examples

- [Examples](./exemples/main.tf)

## Features

- 🖥️ **Windows Feature Management** - Install/uninstall Windows features
- 🔑 **Registry Management** - Create/modify registry keys and values
- 👤 **User Management** - Create and manage local user accounts
- 👥 **Group Management** - Manage local groups and memberships
- ⚙️ **Service Management** - Create, configure, and manage Windows services
- 🏷️ **Hostname Configuration** - Set and manage server hostname
- 🔐 **SSH Connection** - Secure remote management via SSH
- 📝 **PowerShell Execution** - Remote PowerShell command execution

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
| 0.0.7            | >= 1.0           | >= 1.18    |

## Support

For issues, questions, or feature requests, please open an issue on [GitHub Issues](https://github.com/kfrlabs/terraform-provider-windows/issues).

For commercial support, contact the maintainer directly.

## Roadmap

### Planned Features

- **windows_package** : Install or uninstall applications via MSI, EXE, or winget. Version management and source handling (local or network).
- **windows_file** : Create and modify files.
- **windows_directory** : Create and modify directories.
- **windows_acl** : Manage ACLs for security (permissions).
- **windows_firewall** : Manage Windows Firewall configuration.
- **windows_firewall_rule** : Create and manage firewall rules.

## License

See LICENSE file for details.

### new struct

terraform-provider-windows/
├── main.go                          # Point d'entrée (MIGRÉ)
├── internal/
|   ├── common/
│       └── provider_data.go
│   ├── provider/
│   │   ├── provider.go              # Provider principal (MIGRÉ)
│   │   ├── provider_test.go
│   │   └── provider_data.go         # Helper pour données partagées
│   ├── resources/
│   │   ├── resource_feature.go      # À MIGRER
│   │   ├── resource_hostname.go     # À MIGRER
│   │   ├── resource_localuser.go    # À MIGRER
│   │   ├── resource_localgroup.go   # À MIGRER
│   │   └── ...
│   ├── datasources/
│   │   ├── datasource_feature.go    # À MIGRER
│   │   └── ...
│   ├── validators/                  # Custom validators
│   │   ├── powershell_string.go
│   │   └── windows_feature.go
│   └── ssh/                         # Client SSH (inchangé)
│       ├── client.go
│       ├── clixml_parser.go
│       └── pool.go
├── examples/                        # Exemples Terraform
└── docs/                           # Documentation générée