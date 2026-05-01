# Read an existing built-in firewall rule (read-only, no lifecycle management).
data "windows_firewall_rule" "file_sharing" {
  name = "FPS-NB_Session-In-TCP"
}

output "file_sharing_enabled" {
  value = data.windows_firewall_rule.file_sharing.enabled
}

output "file_sharing_action" {
  value = data.windows_firewall_rule.file_sharing.action
}

# Inspect a rule managed by the windows_firewall_rule resource in the same
# configuration. The data source returns the observed live state, including
# fields that the resource may compute (policy_store, edge_traversal_policy).
data "windows_firewall_rule" "managed" {
  name = windows_firewall_rule.allow_app.name
}

# Look up a rule in a non-default policy store.
data "windows_firewall_rule" "gp_rule" {
  name         = "GroupPolicy-Inbound-RDP"
  policy_store = "GroupPolicy"
}
