# Certificate import (PEM variant). Gated: it writes to the machine store
# (removed again on destroy). Uses the committed throwaway self-signed test
# certificate (public material only, CN tf-cert-fixture.example.com) - no
# secrets involved.
resource "windows_certificate" "fixture" {
  count = var.enable_certificate_tests ? 1 : 0

  certificate_pem = file("${path.module}/test-cert.pem")
  friendly_name   = "CliTest-${var.test_suffix}"

  # CLI-level coverage for the timeouts block: parsed by validate and the
  # mocked suite on every PR (offline CI job), honoured on --apply runs.
  # Written with `=` (not a block): like every other SingleNestedAttribute
  # in this provider, `timeouts` only accepts the assignment form.
  timeouts = {
    create = "10m"
    delete = "10m"
  }

  # Replacing a certificate removes the old thumbprint and adds the new one.
  # Create the replacement first so the store always holds a usable
  # certificate during rotation.
  lifecycle {
    create_before_destroy = true
  }
}
