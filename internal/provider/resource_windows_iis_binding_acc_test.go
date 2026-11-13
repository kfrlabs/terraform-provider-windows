//go:build acceptance

// Package provider — acceptance tests for windows_iis_binding.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled and IIS installed (Web-Server). The
//     accEnsureIIS helper (shared with the windows_iis_app_pool suite)
//     installs the feature when it is missing.
//
// Every test uses a dedicated site name so parallel runs never collide,
// and destroys what it creates (bindings are removed on destroy; the
// CheckDestroy assertion below verifies the binding is gone afterwards).
// The https test mints throwaway self-signed certificates directly into
// Cert:\LocalMachine\My (private key included) so the binding can
// reference a real thumbprint; the mint helper removes them in t.Cleanup
// after the binding is destroyed.
package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccIISBindingPreCheck(t *testing.T) {
	t.Helper()
	testAccIISSitePreCheck(t)
}

// testAccCheckIISBindingDestroy asserts every managed binding is gone from IIS.
func testAccCheckIISBindingDestroy(s *terraform.State) error {
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		return fmt.Errorf("winclient.New: %w", err)
	}
	defer func() { _ = c.Close() }()
	bindings := winclient.NewIISBindingClient(c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "windows_iis_binding" {
			continue
		}
		site, proto, bi, err := winclient.ParseIISBindingID(rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("destroy check for %s: %w", rs.Primary.ID, err)
		}
		got, err := bindings.Read(ctx, site, proto, bi)
		if err != nil {
			return fmt.Errorf("destroy check for %s: %w", rs.Primary.ID, err)
		}
		if got != nil {
			return fmt.Errorf("IIS binding %s still present after destroy", rs.Primary.ID)
		}
	}
	return nil
}

// testAccIISBindingSiteBlock renders a zero-binding site for the binding to attach to.
func testAccIISBindingSiteBlock(site string) string {
	return fmt.Sprintf(`
resource "windows_iis_site" "host" {
  name          = %[1]q
  physical_path = "C:\\inetpub\\wwwroot"
}
`, site)
}

// TestAccWindowsIISBinding_Basic — http binding lifecycle: create with a
// canonical identity, drift-free re-plan, import round-trip.
func TestAccWindowsIISBinding_Basic(t *testing.T) {
	testAccIISBindingPreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-bind-basic"
	config := testAccIISBindingSiteBlock(site) + `
resource "windows_iis_binding" "http" {
  site_name   = windows_iis_site.host.name
  protocol    = "http"
  ip_address  = "*"
  port        = 18081
  host_header = "tf-acc-bind.example.com"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISBindingDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_iis_binding.http", "id", site+"|http|*:18081:tf-acc-bind.example.com"),
					resource.TestCheckResourceAttr("windows_iis_binding.http", "binding_information", "*:18081:tf-acc-bind.example.com"),
					resource.TestCheckResourceAttr("windows_iis_binding.http", "protocol", "http"),
					resource.TestCheckResourceAttr("windows_iis_binding.http", "port", "18081"),
				),
			},
			{
				Config:   config,
				PlanOnly: true,
			},
			{
				ResourceName:      "windows_iis_binding.http",
				ImportState:       true,
				ImportStateId:     site + "|http|*:18081:tf-acc-bind.example.com",
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccWindowsIISBinding_HTTPUpdateReplaces — identity attributes are
// ForceNew: changing the host header replaces the binding.
func TestAccWindowsIISBinding_HTTPUpdateReplaces(t *testing.T) {
	testAccIISBindingPreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-bind-replace"
	host1 := "tf-acc-replace-a.example.com"
	host2 := "tf-acc-replace-b.example.com"
	config := func(host string) string {
		return testAccIISBindingSiteBlock(site) + fmt.Sprintf(`
resource "windows_iis_binding" "http" {
  site_name   = windows_iis_site.host.name
  protocol    = "http"
  port        = 18082
  host_header = %q
}
`, host)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISBindingDestroy,
		Steps: []resource.TestStep{
			{
				Config: config(host1),
				Check: resource.TestCheckResourceAttr(
					"windows_iis_binding.http", "binding_information", "*:18082:"+host1),
			},
			{
				Config: config(host2),
				Check: resource.TestCheckResourceAttr(
					"windows_iis_binding.http", "binding_information", "*:18082:"+host2),
			},
		},
	})
}

// TestAccWindowsIISBinding_HTTPSRotation — https binding with SNI plus a
// certificate, then an in-place certificate rotation to a second minted
// certificate (no replacement).
func TestAccWindowsIISBinding_HTTPSRotation(t *testing.T) {
	testAccIISBindingPreCheck(t)
	accEnsureIIS(t)

	cert1 := testAccCertificateMint(t, "pem", true)
	cert2 := testAccCertificateMint(t, "pem", true)

	const site = "tf-acc-bind-https"
	host := "tf-acc-https.example.com"
	config := func(thumb string) string {
		return testAccIISBindingSiteBlock(site) + fmt.Sprintf(`
resource "windows_iis_binding" "https" {
  site_name              = windows_iis_site.host.name
  protocol               = "https"
  port                   = 18443
  host_header            = %q
  require_sni            = true
  certificate_thumbprint = %q
}
`, host, thumb)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISBindingDestroy,
		Steps: []resource.TestStep{
			{
				Config: config(cert1.Thumbprint),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_iis_binding.https", "binding_information", "*:18443:"+host),
					resource.TestCheckResourceAttr("windows_iis_binding.https", "require_sni", "true"),
					resource.TestCheckResourceAttr("windows_iis_binding.https", "certificate_thumbprint", cert1.Thumbprint),
				),
			},
			{
				Config: config(cert2.Thumbprint),
				Check: resource.TestCheckResourceAttr(
					"windows_iis_binding.https", "certificate_thumbprint", cert2.Thumbprint),
			},
		},
	})
}

// TestAccWindowsIISBinding_Conflict — the same listener on two sites is a
// conflict error naming the other site.
func TestAccWindowsIISBinding_Conflict(t *testing.T) {
	testAccIISBindingPreCheck(t)
	accEnsureIIS(t)

	const siteA = "tf-acc-bind-conf-a"
	const siteB = "tf-acc-bind-conf-b"
	config := testAccIISBindingSiteBlock(siteA) + fmt.Sprintf(`
resource "windows_iis_site" "other" {
  name          = %[1]q
  physical_path = "C:\\inetpub\\wwwroot"
}

resource "windows_iis_binding" "first" {
  site_name   = windows_iis_site.host.name
  protocol    = "http"
  port        = 18083
  host_header = "tf-acc-conflict.example.com"
}

resource "windows_iis_binding" "second" {
  site_name   = windows_iis_site.other.name
  protocol    = "http"
  port        = 18083
  host_header = "tf-acc-conflict.example.com"
}
`, siteB)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISBindingDestroy,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`(?i)conflict`),
			},
		},
	})
}

// TestAccWindowsIISBinding_Lockout — binding the SSH management port is a
// would_lock_out refusal before anything is applied.
func TestAccWindowsIISBinding_Lockout(t *testing.T) {
	testAccIISBindingPreCheck(t)
	accEnsureIIS(t)

	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	sshPort := cfg.Port
	if sshPort <= 0 || sshPort > 65535 {
		sshPort = 22
	}

	const site = "tf-acc-bind-lock"
	config := testAccIISBindingSiteBlock(site) + fmt.Sprintf(`
resource "windows_iis_binding" "ssh" {
  site_name = windows_iis_site.host.name
  protocol  = "http"
  port      = %d
}
`, sshPort)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISBindingDestroy,
		Steps: []resource.TestStep{
			{
				Config:      config,
				ExpectError: regexp.MustCompile(`would_lock_out`),
			},
		},
	})
}
