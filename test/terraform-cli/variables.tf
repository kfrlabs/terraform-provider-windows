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
  description = "Temporary password for the fixture local user. Supply through TF_VAR_svc_password or an untracked terraform.tfvars file; do not commit it."
}

variable "enable_firewall_tests" {
  type        = bool
  default     = false
  description = "Enable windows_firewall_rule (+ data source) and windows_firewall_profile (+ data source). Off in containers: WFAS is unavailable there (endpoint mapper error). Enable against a full Windows host/VM."
}

variable "enable_network_config_tests" {
  type        = bool
  default     = false
  description = "Enable windows_dns_client / windows_net_ip_address / windows_net_route (+ data sources). Targets the secondary NIC 'Ethernet 2' (absent in containers) and reconfigures host networking - dedicated throwaway host only."
}

variable "enable_smb_tests" {
  type        = bool
  default     = false
  description = "Enable windows_smb_share (+ data source). Creates a network-visible share - keep off on shared hosts."
}

variable "enable_certificate_tests" {
  type        = bool
  default     = false
  description = "Enable windows_certificate (+ data source). Imports a throwaway self-signed test certificate into the machine store (removed on destroy)."
}

variable "enable_domain_membership_test" {
  type        = bool
  default     = false
  description = "Enable windows_domain_membership. NEVER enable by default: joining an AD domain changes the machine identity and leaves the host reboot-pending. Dedicated throwaway domain-lab host only."
}

variable "domain_join_username" {
  type        = string
  default     = "joiner@corp.example.com"
  description = "Domain account (UPN) used for the join. Only used when enable_domain_membership_test is true."
}

variable "domain_join_password" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Write-only domain password for the join. Supply through TF_VAR_domain_join_password; never commit it. Only used when enable_domain_membership_test is true."
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
