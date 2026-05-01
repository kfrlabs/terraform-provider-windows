---
page_title: "windows_firewall_rule Resource - terraform-provider-windows"
subcategory: ""
description: |-
  Manages a Windows Defender Firewall with Advanced Security rule on a remote Windows host via WinRM and PowerShell (NetSecurity module). One Terraform resource maps to exactly one NetFirewallRule, keyed on its stable technical Name (InstanceID).
---

# windows_firewall_rule (Resource)

Manages a Windows Defender Firewall with Advanced Security rule on a remote
Windows host via WinRM and PowerShell (`NetSecurity` module).

One Terraform resource maps to exactly one `NetFirewallRule`, identified by its
stable technical `name` (InstanceID), which is distinct from `display_name`.
Multiple rules may share the same `display_name`; the provider always keys on
`name` to avoid ambiguity.

Filter sub-objects (`protocol`, `local_port`, `remote_port`, `local_address`,
`remote_address`, `program`, `service`, `interface_type`) are read via the
associated `Get-NetFirewall*Filter` pipeline and updated in a single
`Set-NetFirewallRule` call, keeping mutations atomic.

~> **ForceNew attributes.** Changing `name`, `group`, or `policy_store` destroys
and recreates the rule. For `Allow` rules this causes a brief traffic gap; plan
maintenance windows accordingly.

~> **Read-only stores.** `GroupPolicy` and `RSOP` policy stores are read-only
at runtime. Create/Update/Delete against these stores returns an explicit error.
Use GPO management tools for those stores.

~> **Locale invariance.** The provider pins the PowerShell session to
`InvariantCulture` so enum values are always returned in canonical English
regardless of the host locale (ADR-FR-5).

## Example Usage

### Minimal — allow inbound HTTPS

```terraform
resource "windows_firewall_rule" "allow_https" {
  name         = "Allow-Inbound-HTTPS"
  display_name = "Allow Inbound HTTPS"
  description  = "Permits inbound TCP/443 -- managed by Terraform."
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["443"]
  profile      = ["Domain", "Private"]
}
```

### Block outbound to a specific subnet

```terraform
resource "windows_firewall_rule" "block_outbound" {
  name           = "Block-Outbound-Rogue-IP"
  display_name   = "Block Outbound to 198.51.100.0/24"
  direction      = "Outbound"
  action         = "Block"
  remote_address = ["198.51.100.0/24"]
}
```

### Application-scoped rule

```terraform
resource "windows_firewall_rule" "allow_myapp" {
  name         = "Allow-MyApp-Outbound"
  display_name = "Allow MyApp Outbound"
  direction    = "Outbound"
  action       = "Allow"
  program      = "C:\\Program Files\\MyApp\\myapp.exe"
  profile      = ["Any"]
}
```

### Grouped rules (bulk enable/disable)

```terraform
resource "windows_firewall_rule" "web_http" {
  name         = "Allow-Inbound-HTTP"
  display_name = "Allow Inbound HTTP"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["80"]
  group        = "WebServer"
}

resource "windows_firewall_rule" "web_https" {
  name         = "Allow-Inbound-HTTPS-Grp"
  display_name = "Allow Inbound HTTPS (group)"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["443"]
  group        = "WebServer"
}
```

## Schema

### Required

- `action` (String) Action taken on matching traffic. One of: `Allow`, `Block`, `NotConfigured`.
- `direction` (String) Traffic direction the rule matches. One of: `Inbound`, `Outbound`.
- `display_name` (String) Human-readable name shown in the Windows Firewall UI. Must be non-empty.
- `name` (String) Stable technical identifier of the firewall rule (InstanceID). Used as the Terraform resource ID. **Immutable after creation (ForceNew).** Max 1024 characters; null bytes are not permitted.

### Optional

- `description` (String) Free-form description of the firewall rule. Mutable in-place.
- `edge_traversal_policy` (String) Behaviour for edge-traversed traffic (e.g. Teredo). One of: `Block`, `Allow`, `DeferToUser`, `DeferToApp`. Populated by Windows default when not specified.
- `enabled` (Boolean) Whether the rule is active. Defaults to `true` on creation.
- `group` (String) Rule group (RuleGroup) for bulk operations. **Immutable after creation (ForceNew).**
- `interface_type` (String) Network interface type the rule applies to. One of: `Any`, `Wireless`, `Wired`, `RemoteAccess`. Populated from `Get-NetFirewallInterfaceTypeFilter`.
- `local_address` (List of String) Local IPv4/IPv6 addresses, CIDR ranges, A-B ranges, or keywords (`Any`, `LocalSubnet`, `DNS`, `DHCP`, `WINS`, `DefaultGateway`, `Internet`, `Intranet`, `IntranetRemoteAccess`, `PlayToDevice`). Populated from `Get-NetFirewallAddressFilter`.
- `local_port` (List of String) Local TCP/UDP port(s). Accepts numeric ports, ranges (e.g. `"8000-8100"`), and keywords (`Any`, `RPC`, `RPCEPMap`, `IPHTTPS`, `Teredo`). Valid only when `protocol` is `TCP` or `UDP` (enforced by CV-2). Populated from `Get-NetFirewallPortFilter`.
- `policy_store` (String) Policy store the rule lives in. Defaults to `PersistentStore` (local). **Immutable after creation (ForceNew).** Only `PersistentStore` is fully supported for write operations. One of: `PersistentStore`, `ActiveStore`, `GroupPolicy`, `RSOP`, `SystemDefaults`, `StaticServiceStore`, `ConfigurableServiceStore`.
- `profile` (List of String) Network profiles the rule applies to. Valid elements: `Any`, `Domain`, `Private`, `Public`, `NotApplicable`. `Any` must appear alone (enforced by CV-1 — see Validation section).
- `program` (String) Full path to the matched program executable, or `"Any"`. Environment variables (e.g. `%ProgramFiles%`) are preserved verbatim. Populated from `Get-NetFirewallApplicationFilter`.
- `protocol` (String) IP protocol matched by the rule. Accepts keywords (`TCP`, `UDP`, `ICMPv4`, `ICMPv6`, `IGMP`, `Any`) or a numeric string `0-255` (e.g. `"47"` for GRE). Populated from `Get-NetFirewallPortFilter`.
- `remote_address` (List of String) Remote addresses. Same constraints and keywords as `local_address`. Populated from `Get-NetFirewallAddressFilter`.
- `remote_port` (List of String) Remote TCP/UDP port(s). Same constraints as `local_port`. Populated from `Get-NetFirewallPortFilter`.
- `service` (String) Short name of the matched Windows service, or `"Any"`. Populated from `Get-NetFirewallServiceFilter`.

### Read-Only

- `id` (String) Resource identifier. Set to the technical firewall rule Name (InstanceID) on creation and stable across `display_name` or profile changes.

## Validation

### CV-1 — Profile exclusivity

The `profile` list must not mix `"Any"` with other profile values
(`Domain`, `Private`, `Public`, `NotApplicable`). PowerShell normalises such a
combination to `"Any"` on the next Read, which would produce a permanent drift.

Use `["Any"]` alone for all profiles, or list explicit profiles without `"Any"`.

### CV-2 — Ports only with TCP or UDP

`local_port` and `remote_port` are only accepted when `protocol` is explicitly
set to `TCP` or `UDP`. Setting ports for any other protocol (e.g. `ICMPv4`,
`Any`) is rejected at `terraform plan` time.

## Empty-list normalisation

Windows returns empty arrays for filter attributes that match "Any". The
provider normalises these to `["Any"]` in Terraform state (ADR-FR-6) to prevent
permadiff. Users who omit a filter attribute will see `["Any"]` in
`terraform show` after the first `apply`.

## Import

Import a rule in the default `PersistentStore` by its technical `name`:

```shell
terraform import windows_firewall_rule.example Allow-Inbound-HTTPS
```

Import a rule from an explicit policy store using the format
`<policy_store>/<name>`:

```shell
terraform import windows_firewall_rule.example ActiveStore/Allow-Inbound-HTTPS
```

## Permissions Required

- Local Administrator on the target Windows host (member of `BUILTIN\Administrators`).
- WinRM enabled and reachable; user must be allowed in the PSSessionConfiguration
  (default: `Microsoft.PowerShell`).
- For `GroupPolicy` or `RSOP` stores: GPO read rights (write operations are
  not supported by this resource and will return an explicit error).
