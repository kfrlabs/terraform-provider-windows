---
page_title: "windows Provider"
subcategory: ""
description: |-
  The windows provider manages Windows resources over WinRM.
---

# windows Provider

The `windows` provider manages Windows resources over WinRM.

## Example Usage

```terraform
terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
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

## Schema

See [Schema reference](#) once generated via `tfplugindocs`.
