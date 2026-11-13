//go:build acceptance

// Package provider — acceptance tests for the windows_power_plan data source.
//
// Requires TF_ACC=1 plus a Windows target with power plans available
// (see resource_windows_power_plan_acc_test.go). On targets without
// power plans (containers) the suite skips with a visible reason instead
// of failing; the skip is allow-listed in
// .github/testacc-allowed-skips.json.
package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccWindowsPowerPlanDataSource_Basic — read the singleton active plan
// and the plan list.
func TestAccWindowsPowerPlanDataSource_Basic(t *testing.T) {
	testAccPowerPlanPreCheck(t)
	accPowerPlanEnsureListable(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_power_plan" "current" {}
`,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.windows_power_plan.current", "id"),
					resource.TestCheckResourceAttrSet("data.windows_power_plan.current", "plan_guid"),
					resource.TestMatchResourceAttr("data.windows_power_plan.current", "plan_guid", regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)),
					resource.TestCheckResourceAttrSet("data.windows_power_plan.current", "plan_name"),
				),
			},
		},
	})
}
