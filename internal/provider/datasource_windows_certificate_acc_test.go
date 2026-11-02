//go:build acceptance

// Package provider — acceptance tests for the windows_certificate data source.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled.
//
// The fixture certificate is minted on the target by the shared
// testAccCertificateMint helper (keep = true, so the store entry stays for
// the lookups and is removed in t.Cleanup): no committed key material.
package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccCertificateDataSourcePreCheck(t *testing.T) {
	t.Helper()
	testAccCertificatePreCheck(t)
}

// TestAccWindowsCertificateDataSource_Basic — lookup by thumbprint and by
// subject against the same minted certificate, plus the not-found case.
func TestAccWindowsCertificateDataSource_Basic(t *testing.T) {
	testAccCertificateDataSourcePreCheck(t)
	minted := testAccCertificateMint(t, "pem", true)

	cfg := fmt.Sprintf(`
data "windows_certificate" "by_thumbprint" {
  thumbprint = %[1]q
}

data "windows_certificate" "by_subject" {
  subject = %[2]q
}
`, minted.Thumbprint, minted.Subject)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.windows_certificate.by_thumbprint", "subject", minted.Subject),
					resource.TestCheckResourceAttr("data.windows_certificate.by_thumbprint", "thumbprint", minted.Thumbprint),
					resource.TestCheckResourceAttr("data.windows_certificate.by_thumbprint", "has_private_key", "false"),
					resource.TestCheckResourceAttr("data.windows_certificate.by_thumbprint", "dns_names.0", minted.DNSName),
					resource.TestCheckResourceAttr("data.windows_certificate.by_subject", "thumbprint", minted.Thumbprint),
					resource.TestCheckResourceAttr("data.windows_certificate.by_subject", "subject", minted.Subject),
				),
			},
		},
	})
}

// TestAccWindowsCertificateDataSource_NotFound pins the not-found
// diagnostic for an absent thumbprint.
func TestAccWindowsCertificateDataSource_NotFound(t *testing.T) {
	testAccCertificateDataSourcePreCheck(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "windows_certificate" "missing" {
  thumbprint = "0000000000000000000000000000000000000000"
}
`,
				ExpectError: regexp.MustCompile(`Data source not found`),
			},
		},
	})
}
