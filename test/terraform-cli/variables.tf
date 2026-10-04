variable "windows_host" {
  type        = string
  description = "Address of the Windows target (tfacc-win container or real host)."
}

variable "windows_port" {
  type        = number
  default     = 2222
  description = "SSH port published by the target."
}

variable "windows_username" {
  type        = string
  default     = "tfacc"
  description = "SSH local admin account on the target."
}

variable "windows_password" {
  type        = string
  sensitive   = true
  description = "Password for windows_username. Throwaway lab credential only."
}

variable "windows_insecure_ignore_host_key" {
  type        = bool
  default     = true
  description = "Lab only: the container regenerates its host key on rebuild. Never true against production."
}

variable "test_suffix" {
  type        = string
  default     = "cli"
  description = "Suffix for every object created, to avoid collisions with the Go suite or test/terraform fixtures."
}

variable "svc_password" {
  type        = string
  sensitive   = true
  default     = "Xk7!mQ2#nR9w"
  description = "Password for the fixture local user and scheduled-task principal. Must not contain the account name."
}

variable "enable_firewall_tests" {
  type        = bool
  default     = false
  description = "Enable windows_firewall_rule (+ data source). Off in containers: WFAS is unavailable there (endpoint mapper error). Enable against a full Windows host/VM."
}

variable "enable_network_tests" {
  type        = bool
  default     = false
  description = "Enable windows_legacy_package / windows_winget_package (needs container internet + App Installer)."
}

variable "enable_feature_test" {
  type        = bool
  default     = false
  description = "Enable windows_feature (slow DISM, payload often missing in containers)."
}

variable "enable_hostname_test" {
  type        = bool
  default     = false
  description = "Enable windows_hostname rename. Renames the machine (reboot-pending) - keep off on shared lab hosts."
}

variable "expected_hostname" {
  type        = string
  default     = "TFACC-WIN"
  description = "Only used when enable_hostname_test is true: the name windows_hostname must converge to."
}
