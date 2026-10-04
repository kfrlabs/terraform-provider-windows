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
}

variables {
  windows_host          = "192.0.2.1"
  windows_port          = 2222
  windows_username      = "tfacc"
  windows_password      = "mock-only-no-network"
  test_suffix           = "mock"
  enable_firewall_tests = true
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
}
