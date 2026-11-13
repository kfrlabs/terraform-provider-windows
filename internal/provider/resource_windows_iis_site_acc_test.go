//go:build acceptance

// Package provider — acceptance tests for windows_iis_site.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled and IIS installed (Web-Server). The
//     suite installs the Web-Server feature (with management tools, which
//     brings the WebAdministration module on Server Core) when it is missing
//     and skips when the install fails (accEnsureIIS, shared with the
//     windows_iis_app_pool suite).
//
// Every test uses a dedicated site name so parallel runs never collide,
// and destroys what it creates (sites are removed on destroy; the
// CheckDestroy assertion below verifies the site is gone afterwards).
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

func testAccIISSitePreCheck(t *testing.T) {
	t.Helper()
	testAccIISAppPoolPreCheck(t)
}

// testAccCheckIISSiteDestroy asserts every managed site is gone from IIS.
func testAccCheckIISSiteDestroy(s *terraform.State) error {
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
	sites := winclient.NewIISSiteClient(c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "windows_iis_site" {
			continue
		}
		got, err := sites.Read(ctx, rs.Primary.ID)
		if err != nil {
			return fmt.Errorf("destroy check for %s: %w", rs.Primary.ID, err)
		}
		if got != nil {
			return fmt.Errorf("IIS site %s still present after destroy", rs.Primary.ID)
		}
	}
	return nil
}

// TestAccWindowsIISSite_Basic — create with a partial configuration
// (zero bindings), drift-free re-plan, then update path and pool in place.
func TestAccWindowsIISSite_Basic(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-site-basic"
	const pool = "tf-acc-site-pool"
	createCfg := fmt.Sprintf(`
resource "windows_feature" "iis" {
  name                     = "Web-Server"
  include_management_tools = true
}

resource "windows_iis_app_pool" "site" {
  name = %[2]q

  depends_on = [windows_feature.iis]
}

resource "windows_iis_app_pool" "site2" {
  name = %[2]q2

  depends_on = [windows_feature.iis]
}

resource "windows_directory" "extra" {
  path = "C:\\inetpub\\tf-acc-site"
}

resource "windows_iis_site" "acc" {
  name             = %[1]q
  physical_path    = "C:\\inetpub\\wwwroot"
  application_pool = windows_iis_app_pool.site.name
  auto_start       = true
  log_format       = "W3C"

  depends_on = [windows_feature.iis]
}
`, site, pool)
	updateCfg := fmt.Sprintf(`
resource "windows_feature" "iis" {
  name                     = "Web-Server"
  include_management_tools = true
}

resource "windows_iis_app_pool" "site" {
  name = %[2]q

  depends_on = [windows_feature.iis]
}

resource "windows_iis_app_pool" "site2" {
  name = %[2]q2

  depends_on = [windows_feature.iis]
}

resource "windows_directory" "extra" {
  path = "C:\\inetpub\\tf-acc-site"
}

resource "windows_iis_site" "acc" {
  name             = %[1]q
  physical_path    = windows_directory.extra.path
  application_pool = windows_iis_app_pool.site2.name
  auto_start       = false
  log_format       = "IIS"

  depends_on = [windows_feature.iis]
}
`, site, pool)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISSiteDestroy,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_iis_site.acc", "id", site),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "name", site),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "physical_path", `C:\inetpub\wwwroot`),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "application_pool", pool),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "auto_start", "true"),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "log_format", "W3C"),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "bindings.#", "0"),
				),
			},
			{
				Config:   createCfg,
				PlanOnly: true,
			},
			{
				Config: updateCfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_iis_site.acc", "physical_path", `C:\inetpub\tf-acc-site`),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "application_pool", pool+"2"),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "auto_start", "false"),
					resource.TestCheckResourceAttr("windows_iis_site.acc", "log_format", "IIS"),
				),
			},
		},
	})
}

// TestAccWindowsIISSite_ZeroBindingsStarted — a Started site with no
// bindings stays Stopped with a warning instead of failing; the
// suppression modifier keeps the follow-up plan empty.
func TestAccWindowsIISSite_ZeroBindingsStarted(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-site-unbound"
	config := fmt.Sprintf(`
resource "windows_iis_site" "unbound" {
  name          = %[1]q
  physical_path = "C:\\inetpub\\wwwroot"
  state         = "Started"
}
`, site)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISSiteDestroy,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					// IIS cannot run an unbound site: the create warns
					// and the host stays Stopped.
					resource.TestCheckResourceAttr("windows_iis_site.unbound", "state", "Stopped"),
					resource.TestCheckResourceAttr("windows_iis_site.unbound", "bindings.#", "0"),
				),
			},
			{
				Config:   config,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsIISSite_StopStart — state = Stopped is enforced on an
// unbound site, and switching back to Started keeps the site Stopped
// (with a warning) instead of failing.
func TestAccWindowsIISSite_StopStart(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-site-stopstart"
	cfg := func(state string) string {
		return fmt.Sprintf(`
resource "windows_iis_site" "tog" {
  name          = %[1]q
  physical_path = "C:\\inetpub\\wwwroot"
  state         = %[2]q
}
`, site, state)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISSiteDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg("Stopped"),
				Check:  resource.TestCheckResourceAttr("windows_iis_site.tog", "state", "Stopped"),
			},
			{
				Config: cfg("Started"),
				Check:  resource.TestCheckResourceAttr("windows_iis_site.tog", "state", "Stopped"),
			},
		},
	})
}

// TestAccWindowsIISSite_Import — import an existing site by name.
func TestAccWindowsIISSite_Import(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-site-imp"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISSiteDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_site" "imp" {
  name              = %[1]q
  physical_path     = "C:\\inetpub\\wwwroot"
  auto_start        = true
  enabled_protocols = "http"
}
`, site),
			},
			{
				ResourceName:      "windows_iis_site.imp",
				ImportState:       true,
				ImportStateId:     site,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccWindowsIISSite_SiteID — an explicit site_id is honoured at
// creation.
func TestAccWindowsIISSite_SiteID(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-site-id"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISSiteDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_site" "numbered" {
  name          = %[1]q
  site_id       = 42
  physical_path = "C:\\inetpub\\wwwroot"
}
`, site),
				Check: resource.TestCheckResourceAttr("windows_iis_site.numbered", "site_id", "42"),
			},
		},
	})
}

// TestAccWindowsIISSite_MissingPathFails — a physical_path that does not
// exist is a path_not_found error, never an implicit mkdir.
func TestAccWindowsIISSite_MissingPathFails(t *testing.T) {
	testAccIISSitePreCheck(t)
	accEnsureIIS(t)

	const site = "tf-acc-site-nopath"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckIISSiteDestroy,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_site" "nopath" {
  name          = %[1]q
  physical_path = "C:\\inetpub\\tf-acc-does-not-exist"
}
`, site),
				ExpectError: regexp.MustCompile("path_not_found"),
			},
		},
	})
}
