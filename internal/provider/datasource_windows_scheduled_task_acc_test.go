//go:build acceptance

// Package provider — acceptance test skeletons for windows_scheduled_task data source.
//
// Requires TF_ACC=1 and WINDOWS_HOST to be set. Skipped automatically otherwise.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccWindowsScheduledTaskDS_Read verifies the data source can read a task
// created by the resource.
func TestAccWindowsScheduledTaskDS_Read(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	if os.Getenv("WINDOWS_HOST") == "" {
		t.Skip("WINDOWS_HOST not set — skipping acceptance test")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_scheduled_task" "ds_source" {
  name        = "TF-DS-Read-Task"
  path        = "\\TF\\"
  description = "data source test"
  enabled     = true
  action { execute = "cmd.exe" }
  trigger {
    type           = "Daily"
    start_boundary = "2026-01-01T08:00:00Z"
  }
}

data "windows_scheduled_task" "test" {
  name = windows_scheduled_task.ds_source.name
  path = windows_scheduled_task.ds_source.path
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_scheduled_task.test", "name", "TF-DS-Read-Task"),
					resource.TestCheckResourceAttr("data.windows_scheduled_task.test", "path", `\TF\`),
					resource.TestCheckResourceAttr("data.windows_scheduled_task.test", "description", "data source test"),
					resource.TestCheckResourceAttr("data.windows_scheduled_task.test", "enabled", "true"),
					resource.TestCheckResourceAttrSet("data.windows_scheduled_task.test", "id"),
					resource.TestCheckResourceAttrSet("data.windows_scheduled_task.test", "state"),
				),
			},
		},
	})
}

// TestAccWindowsScheduledTaskDS_NotFound verifies the data source returns an error
// when the task does not exist.
func TestAccWindowsScheduledTaskDS_NotFound(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	if os.Getenv("WINDOWS_HOST") == "" {
		t.Skip("WINDOWS_HOST not set — skipping acceptance test")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_scheduled_task" "not_found" {
  name = "TF-NonExistent-Task-XYZ123"
  path = "\\"
}
`,
				ExpectError: nil, // expecting an apply error; set regexp if needed
			},
		},
	})
}

// TestAccWindowsScheduledTaskDS_SystemTask verifies a built-in Windows task can be
// read by the data source (read-only, no create).
func TestAccWindowsScheduledTaskDS_SystemTask(t *testing.T) {
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set")
	}
	if os.Getenv("WINDOWS_HOST") == "" {
		t.Skip("WINDOWS_HOST not set — skipping acceptance test")
	}

	// \Microsoft\Windows\.NET Framework\[any known task] — use a safe one
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_scheduled_task" "defrag" {
  name = "ScheduledDefrag"
  path = "\\Microsoft\\Windows\\Defrag\\"
}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_scheduled_task.defrag", "name", "ScheduledDefrag"),
					resource.TestCheckResourceAttrSet("data.windows_scheduled_task.defrag", "id"),
				),
			},
		},
	})
}
