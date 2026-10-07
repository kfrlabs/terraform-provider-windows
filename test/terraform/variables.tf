variable "windows_host" {
  type        = string
  description = "Address of the tfacc-win container (or any throwaway Windows target)."
}

variable "windows_port" {
  type        = number
  default     = 2222
  description = "SSH port published by the container (see test/windows-container/README.md)."
}

variable "windows_username" {
  type        = string
  default     = "tfacc"
  description = "Local admin account baked into the tfacc-win image."
}

variable "svc_password" {
  type        = string
  sensitive   = true
  description = "Temporary password for test service users. Supply it out of band; do not commit it."
}

variable "windows_insecure_ignore_host_key" {
  type        = bool
  default     = true
  description = "The container's host key is regenerated on every rebuild, so pinning it is pointless for this fixture. Never set this against a real/production host."
}

variable "enable_network_tests" {
  type        = bool
  default     = false
  description = "Enable windows_legacy_package / windows_winget_package scenarios in packages.tf. Needs outbound internet from the container and, for winget, the App Installer package present in the image (see test/terraform/README.md)."
}

variable "enable_feature_test" {
  type        = bool
  default     = false
  description = "Enable the windows_feature scenario. Slow (DISM) and some roles have no payload inside a minimal container image — see test/terraform/README.md before enabling."
}

variable "test_suffix" {
  type        = string
  default     = "pushed"
  description = "Appended to every object this workspace creates, so it never collides with names the Go acceptance suite uses concurrently against the same container."
}
