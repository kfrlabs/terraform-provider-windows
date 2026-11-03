mock_provider "windows" {
  mock_resource "windows_local_group" {
    defaults = {
      sid = "S-1-5-21-1-2-3-1001"
    }
  }
  mock_resource "windows_local_user" {
    defaults = {
      sid = "S-1-5-21-1-2-3-1002"
    }
  }
  mock_resource "windows_local_group_member" {
    defaults = {
      group_sid  = "S-1-5-21-1-2-3-1001"
      member_sid = "S-1-5-21-1-2-3-1002"
    }
  }
  mock_resource "windows_directory" {
    defaults = {
      exists_children = false
      item_count      = 0
    }
  }
  mock_resource "windows_file" {
    defaults = {
      content_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      size_bytes     = 0
    }
  }
  mock_resource "windows_file_acl" {
    defaults = {
      sddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
    }
  }
  mock_resource "windows_registry_value" {
    defaults = {
      # Matches windows_registry_value.version with test_suffix="mock".
      # (One default per type: sibling REG_* instances return the same mock
      # value, which is fine — no check block covers them.)
      value_string = "1.0.0-mock"
    }
  }
  mock_resource "windows_environment_variable" {
    defaults = {
      # Matches windows_environment_variable.app_home with test_suffix="mock".
      value = "C:\\ProgramData\\cli-test-mock\\appsettings.json"
    }
  }
  mock_resource "windows_firewall_rule" {
    defaults = {}
  }
  mock_resource "windows_scheduled_task" {
    defaults = {
      state = "Ready"
    }
  }
  mock_resource "windows_service" {
    defaults = {
      display_name   = "Mocked"
      current_status = "Stopped"
    }
  }
  mock_resource "windows_firewall_profile" {
    defaults = {
      enabled = true
    }
  }
  mock_resource "windows_dns_client" {
    defaults = {
      effective_ipv4 = ["192.0.2.53", "198.51.100.53"]
    }
  }
  mock_resource "windows_net_ip_address" {
    defaults = {
      address_state = "Preferred"
    }
  }
  mock_resource "windows_net_route" {
    defaults = {
      effective_metric = 10
    }
  }
  mock_resource "windows_smb_share" {
    defaults = {
      special = false
    }
  }
  mock_resource "windows_certificate" {
    defaults = {
      # SHA-1 thumbprint of the committed test-cert.pem fixture.
      thumbprint = "6149A527D8030002108CB908C84A5500DAB7470A"
    }
  }
  mock_resource "windows_domain_membership" {
    # Never enabled in the mocked run (see variables below): declared so the
    # plan shape is covered, with no instances to assert on.
    defaults = {}
  }
  mock_resource "windows_legacy_package" {
    defaults = {
      installed         = true
      installed_version = "24.08"
      product_id        = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
    }
  }
  mock_resource "windows_winget_package" {
    defaults = {
      installed_version = "1.85.2"
      name              = "Visual Studio Code"
    }
  }
  mock_data "windows_local_group" {
    defaults = {
      sid = "S-1-5-21-1-2-3-1001"
    }
  }
  mock_data "windows_local_user" {
    defaults = {
      sid = "S-1-5-21-1-2-3-1002"
    }
  }
  mock_data "windows_local_group_member" {
    defaults = {
      group_sid  = "S-1-5-21-1-2-3-1001"
      member_sid = "S-1-5-21-1-2-3-1002"
    }
  }
  mock_data "windows_registry_value" {
    defaults = {
      # Must equal the version resource above so the live check block
      # registry_value_agrees also holds under mocks.
      value_string = "1.0.0-mock"
    }
  }
  mock_data "windows_environment_variable" {
    defaults = {
      # Must equal windows_environment_variable.app_home (see above).
      value = "C:\\ProgramData\\cli-test-mock\\appsettings.json"
    }
  }
  mock_data "windows_firewall_rule" {
    defaults = {
      display_name = "Mocked"
      direction    = "Inbound"
      action       = "Allow"
    }
  }
  mock_data "windows_scheduled_task" {
    defaults = {
      state = "Ready"
    }
  }
  mock_data "windows_service" {
    defaults = {
      display_name = "Mocked"
    }
  }
  mock_data "windows_hostname" {
    defaults = {
      current_name   = "MOCK-HOST"
      reboot_pending = false
    }
  }
  mock_data "windows_directory" {
    defaults = {
      # Must equal the directory resource above so the live check block
      # directory_agrees also holds under mocks.
      exists_children = false
      item_count      = 0
    }
  }
  mock_data "windows_file" {
    defaults = {
      # Must equal windows_file.app_config (see above).
      content_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      size_bytes     = 0
    }
  }
  mock_data "windows_file_acl" {
    defaults = {
      # Must equal windows_file_acl.app_config (see above).
      sddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
    }
  }
  mock_data "windows_firewall_profile" {
    defaults = {
      enabled = true
    }
  }
  mock_data "windows_dns_client" {
    defaults = {
      effective_ipv4 = ["192.0.2.53", "198.51.100.53"]
    }
  }
  mock_data "windows_net_ip_address" {
    defaults = {
      address_state = "Preferred"
    }
  }
  mock_data "windows_net_route" {
    defaults = {
      effective_metric = 10
    }
  }
  mock_data "windows_smb_share" {
    defaults = {
      special = false
    }
  }
  mock_data "windows_certificate" {
    defaults = {
      # Must equal the certificate resource above (test-cert.pem).
      thumbprint = "6149A527D8030002108CB908C84A5500DAB7470A"
    }
  }
  mock_data "windows_legacy_package" {
    defaults = {
      installed         = true
      installed_version = "24.08"
    }
  }
  mock_data "windows_winget_package" {
    defaults = {
      installed_version = "1.85.2"
      is_installed      = true
      name              = "Visual Studio Code"
    }
  }
}

variables {
  windows_host                = "192.0.2.1"
  windows_port                = 2222
  windows_username            = "tfacc"
  svc_password                = ""
  test_suffix                 = "mock"
  enable_firewall_tests       = true
  enable_network_tests        = true
  enable_network_config_tests = true
  enable_smb_tests            = true
  enable_certificate_tests    = true
}

run "full_apply" {
  command = apply

  # Spot-check that the wired resources survive a mocked plan.
  assert {
    condition     = windows_local_group.fixture.name == "CliOperators-mock"
    error_message = "local group name did not plan as expected"
  }

  assert {
    condition     = windows_file.app_config.path == "C:\\ProgramData\\cli-test-mock\\appsettings.json"
    error_message = "file path did not plan as expected"
  }

  assert {
    condition     = windows_firewall_rule.allow_inbound[0].direction == "Inbound"
    error_message = "firewall rule direction did not plan as expected"
  }

  assert {
    condition     = windows_firewall_profile.fixture[0].name == "Private"
    error_message = "firewall profile name did not plan as expected"
  }

  assert {
    condition     = windows_dns_client.secondary[0].interface_alias == "Ethernet 2"
    error_message = "dns client interface did not plan as expected"
  }

  assert {
    condition     = windows_net_ip_address.storage[0].ip_address == "192.0.2.10"
    error_message = "net ip address did not plan as expected"
  }

  assert {
    condition     = windows_net_route.backup[0].next_hop == "192.0.2.1"
    error_message = "net route next hop did not plan as expected"
  }

  assert {
    condition     = windows_smb_share.fixture[0].name == "CliTest-mock"
    error_message = "smb share name did not plan as expected"
  }

  assert {
    condition     = data.windows_certificate.fixture[0].thumbprint == windows_certificate.fixture[0].thumbprint
    error_message = "certificate data source thumbprint disagrees under mocks"
  }

  assert {
    condition     = data.windows_smb_share.fixture[0].special == windows_smb_share.fixture[0].special
    error_message = "smb share data source disagrees under mocks"
  }

  assert {
    condition     = data.windows_file.app_config.content_sha256 == windows_file.app_config.content_sha256
    error_message = "file data source disagrees under mocks"
  }

  assert {
    condition     = data.windows_file_acl.app_config.sddl == windows_file_acl.app_config.sddl
    error_message = "file acl data source disagrees under mocks"
  }

  assert {
    condition     = data.windows_directory.app_logs.item_count == windows_directory.app_logs.item_count
    error_message = "directory data source disagrees under mocks"
  }

  assert {
    condition     = data.windows_legacy_package.sevenzip[0].installed == windows_legacy_package.sevenzip[0].installed
    error_message = "legacy package data source disagrees under mocks"
  }
}
