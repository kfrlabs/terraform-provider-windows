//go:build acceptance

// Package provider — acceptance test for the windows_dns_client data source.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - WINDOWS_TEST_INTERFACE set to an explicit secondary interface alias.
//
// SAFETY: read-only — unlike the resource tests, this test never assigns
// addresses. It reads the live DNS state of the secondary interface given
// by WINDOWS_TEST_INTERFACE and only asserts populated computed attributes
// plus echo-back of the alias. The target helper refuses to run on the
// management NIC.
package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccWindowsDNSClientDataSource_Basic reads the DNS client state of the
// secondary test interface and verifies computed attributes are populated.
func TestAccWindowsDNSClientDataSource_Basic(t *testing.T) {
	testAccDNSClientPreCheck(t)
	alias := testAccDNSClientTarget(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`data "windows_dns_client" "test" { interface_alias = %q }`, alias),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_dns_client.test", "id", alias),
					resource.TestCheckResourceAttr("data.windows_dns_client.test", "interface_alias", alias),
					resource.TestCheckResourceAttrSet("data.windows_dns_client.test", "interface_index"),
					resource.TestCheckResourceAttrSet("data.windows_dns_client.test", "interface_guid"),
				),
			},
		},
	})
}
