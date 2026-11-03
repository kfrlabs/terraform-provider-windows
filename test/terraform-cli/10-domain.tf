# Domain membership. NEVER enable by default: joining an AD domain changes
# the machine identity, creates a computer account, and leaves the host
# reboot-pending - dedicated throwaway domain-lab host only. Destroy is a
# no-op (unjoin_on_destroy stays false); the host must be unjoined out of
# band. The join credential is WriteOnly and never reaches state or logs.
resource "windows_domain_membership" "fixture" {
  count = var.enable_domain_membership_test ? 1 : 0

  domain = "corp.example.com" # documentation range, RFC 2606

  join_credential = {
    username    = var.domain_join_username
    password_wo = var.domain_join_password
  }

  # CLI-level coverage for the timeouts block: parsed by validate and the
  # mocked suite on every PR (offline CI job), honoured on --apply runs.
  # Written with `=` (not a block): like every other SingleNestedAttribute
  # in this provider, `timeouts` only accepts the assignment form.
  timeouts = {
    create = "15m"
    delete = "15m"
  }
}
