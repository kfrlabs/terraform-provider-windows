# windows_service in this fixture creates a dedicated, clearly-named service
# rather than reconfiguring a system one. `name` and `binary_path` are both
# ForceNew, and reconfiguring a service the image already ships (e.g.
# W32Time) risks an unwanted replace if the recorded binary_path drifts from
# the image's, so a fresh service on a harmless binary is the stable choice.
# Mirrors what resource_windows_service_acc_test.go does (cmd.exe, Manual).
resource "windows_service" "pushed_test" {
  name         = "PushedTest-${var.test_suffix}"
  display_name = "Pushed-Test Fixture Service (${var.test_suffix})"
  description  = "Created by test/terraform/service.tf — safe to delete."
  binary_path  = "C:\\Windows\\System32\\cmd.exe"
  start_type   = "Manual"
  status       = "Stopped"
}
