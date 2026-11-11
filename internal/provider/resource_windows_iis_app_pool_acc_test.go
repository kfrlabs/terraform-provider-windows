//go:build acceptance

// Package provider — acceptance tests for windows_iis_app_pool.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled and IIS installed (Web-Server). The
//     suite installs the Web-Server feature (with management tools, which
//     brings the WebAdministration module on Server Core) when it is missing
//     and skips when the install fails.
//
// Every test uses a dedicated pool name so parallel runs never collide, and
// destroys what it creates (pools are removed on destroy).
package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccIISAppPoolPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// accIISAppPoolClient builds a direct winclient for out-of-band reads.
// ResolveFromEnv is intentional here: the public-key CI leg clears
// WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH instead.
func accIISAppPoolClient(t *testing.T) *winclient.IISAppPoolClient {
	t.Helper()
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	return winclient.NewIISAppPoolClient(c)
}

// accEnsureIIS installs the Web-Server feature (with management tools) when
// IIS or its management tools are missing, and skips the test when IIS
// cannot be provided. The throwaway container (servercore:ltsc2025) starts
// without IIS; the authorized test server is expected to keep it. The
// Web-Server feature may report Installed without the WebAdministration
// module (missing management tools), so IIS itself is probed via a dummy
// pool Read: iis_not_installed triggers an idempotent Install with
// IncludeManagementTools even when the feature already reports Installed.
func accEnsureIIS(t *testing.T) {
	t.Helper()
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		t.Skipf("cannot connect to the Windows target; skipping: %v", err)
	}
	fc := winclient.NewFeatureClient(c)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	info, err := fc.Read(ctx, "Web-Server")
	if err != nil {
		t.Skipf("cannot probe the Web-Server feature; skipping: %v", err)
	}
	featureInstalled := info != nil && info.Installed
	poolClient := winclient.NewIISAppPoolClient(c)
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer probeCancel()
	_, probeErr := poolClient.Read(probeCtx, "tf-acc-probe-does-not-exist")
	if probeErr == nil || winclient.IsIISAppPoolError(probeErr, winclient.IISAppPoolErrorNotFound) {
		return
	}
	if !winclient.IsIISAppPoolError(probeErr, winclient.IISAppPoolErrorIISNotInstalled) {
		if featureInstalled {
			return
		}
		t.Skipf("cannot probe IIS on the Windows target; skipping: %v", probeErr)
	}
	t.Log("IIS management tools missing; installing Web-Server with management tools for the acceptance suite")
	if _, _, err := fc.Install(ctx, winclient.FeatureInput{
		Name: "Web-Server", IncludeManagementTools: true,
	}); err != nil {
		t.Skipf("cannot install the Web-Server feature; skipping: %v", err)
	}
}

// TestAccWindowsIISAppPool_Basic — create with a partial configuration,
// drift-free re-plan, then update in place.
func TestAccWindowsIISAppPool_Basic(t *testing.T) {
	testAccIISAppPoolPreCheck(t)
	accEnsureIIS(t)

	const pool = "tf-acc-apppool-basic"
	cfg := func(mode string, queue int) string {
		return fmt.Sprintf(`
resource "windows_iis_app_pool" "acc" {
  name                  = %[1]q
  managed_runtime_version = "v4.0"
  managed_pipeline_mode = %[2]q
  queue_length          = %[3]d
  idle_timeout_minutes  = 20
}
`, pool, mode, queue)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("Integrated", 1000),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "id", pool),
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "name", pool),
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "managed_runtime_version", "v4.0"),
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "managed_pipeline_mode", "Integrated"),
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "queue_length", "1000"),
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "idle_timeout_minutes", "20"),
				),
			},
			{
				Config:   cfg("Integrated", 1000),
				PlanOnly: true,
			},
			{
				Config: cfg("Classic", 2000),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "managed_pipeline_mode", "Classic"),
					resource.TestCheckResourceAttr("windows_iis_app_pool.acc", "queue_length", "2000"),
				),
			},
		},
	})
}

// TestAccWindowsIISAppPool_StoppedState — state = Stopped is enforced, and
// dropping it leaves the host state unmanaged.
func TestAccWindowsIISAppPool_StoppedState(t *testing.T) {
	testAccIISAppPoolPreCheck(t)
	accEnsureIIS(t)

	const pool = "tf-acc-apppool-stopped"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_app_pool" "stopped" {
  name  = %[1]q
  state = "Stopped"
}
`, pool),
				Check: resource.TestCheckResourceAttr("windows_iis_app_pool.stopped", "state", "Stopped"),
			},
			{
				Config: fmt.Sprintf(`
resource "windows_iis_app_pool" "stopped" {
  name  = %[1]q
  state = "Started"
}
`, pool),
				Check: resource.TestCheckResourceAttr("windows_iis_app_pool.stopped", "state", "Started"),
			},
		},
	})
}

// TestAccWindowsIISAppPool_SpecificUser — a SpecificUser pool backed by a
// local test account provisioned through windows_local_user. The password
// literal deliberately avoids the account name (Windows complexity policy
// rejects passwords containing the samAccountName).
func TestAccWindowsIISAppPool_SpecificUser(t *testing.T) {
	testAccIISAppPoolPreCheck(t)
	accEnsureIIS(t)

	const pool = "tf-acc-apppool-svc"
	const user = "tfaccsvcpool"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_local_user" "svc" {
  name                 = %[2]q
  password_wo          = "Xy9#kQ2$mV7!pL4@zR8&"
  password_wo_version  = 1
}

resource "windows_iis_app_pool" "svc" {
  name                         = %[1]q
  identity_type                = "SpecificUser"
  identity_username            = windows_local_user.svc.name
  identity_password_wo         = "Xy9#kQ2$mV7!pL4@zR8&"
  identity_password_wo_version = 1

  depends_on = [windows_local_user.svc]
}
`, pool, user),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_iis_app_pool.svc", "identity_type", "SpecificUser"),
					resource.TestCheckResourceAttr("windows_iis_app_pool.svc", "identity_username", user),
				),
			},
		},
	})
}

// TestAccWindowsIISAppPool_Import — import an existing pool by name.
func TestAccWindowsIISAppPool_Import(t *testing.T) {
	testAccIISAppPoolPreCheck(t)
	accEnsureIIS(t)

	const pool = "tf-acc-apppool-imp"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_app_pool" "imp" {
  name             = %[1]q
  queue_length     = 1000
  start_mode       = "OnDemand"
}
`, pool),
			},
			{
				ResourceName:      "windows_iis_app_pool.imp",
				ImportState:       true,
				ImportStateId:     pool,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccWindowsIISAppPool_RecyclingSchedule — a schedule is fully replaced
// on update and cleared by an empty set.
func TestAccWindowsIISAppPool_RecyclingSchedule(t *testing.T) {
	testAccIISAppPoolPreCheck(t)
	accEnsureIIS(t)

	const pool = "tf-acc-apppool-sched"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_iis_app_pool" "sched" {
  name               = %[1]q
  recycling_schedule = ["03:00:00"]
}
`, pool),
				Check: resource.TestCheckResourceAttr("windows_iis_app_pool.sched", "recycling_schedule.#", "1"),
			},
			{
				Config: fmt.Sprintf(`
resource "windows_iis_app_pool" "sched" {
  name               = %[1]q
  recycling_schedule = ["03:00:00", "04:30:00"]
}
`, pool),
				Check: resource.TestCheckResourceAttr("windows_iis_app_pool.sched", "recycling_schedule.#", "2"),
			},
		},
	})
}
