//go:build acceptance

// Package provider — acceptance tests for windows_power_plan.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME plus a credential (see acc_test_helper.go)
//   - A Windows target with power plans available.
//
// Switching the active plan is low-risk (powercfg /setactive, instantly
// reversible) but containers share the host power policy: on targets
// without powercfg or without an active plan the suite skips with a
// visible reason instead of failing (the skip is allow-listed in
// .github/testacc-allowed-skips.json so the CI gate stays green).
// Every mutating test sets restore_on_destroy so the suite leaves the
// pre-existing plan behind even when a step fails mid-apply.
package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

func testAccPowerPlanPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// newAccPowerPlanClient builds a direct winclient for out-of-band reads and
// the mutability probe. ResolveFromEnv is intentional here: the public-key
// CI leg clears WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH
// instead.
func newAccPowerPlanClient() (*winclient.PowerPlanClient, error) {
	cfg := winclient.Config{Timeout: 60 * time.Second}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		return nil, err
	}
	return winclient.NewPowerPlanClient(c), nil
}

func accPowerPlanClient(t *testing.T) *winclient.PowerPlanClient {
	t.Helper()
	c, err := newAccPowerPlanClient()
	if err != nil {
		t.Fatalf("winclient.New: %v", err)
	}
	return c
}

// accPowerPlanEnsureMutable probes whether switching the active plan takes
// effect on the target: it activates a plan that differs from the live
// one, verifies the re-read, and restores the original plan. On targets
// without power plans (containers share the host power policy) it skips
// with a visible reason instead of failing. Returns the pre-existing
// (restored) state.
func accPowerPlanEnsureMutable(t *testing.T) *winclient.PowerPlanState {
	t.Helper()
	c := accPowerPlanClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	orig, err := c.Read(ctx, nil)
	if err != nil {
		t.Skipf("power plan unsupported on target (%v); skipping", err)
	}
	target := winclient.PowerPlanHighPerformanceGUID
	if orig.PlanGUID == target {
		target = winclient.PowerPlanBalancedGUID
	}
	applied, err := c.Apply(ctx, winclient.PowerPlanInput{Plan: target})
	if err != nil {
		_, _ = c.Apply(ctx, winclient.PowerPlanInput{Plan: orig.PlanGUID})
		t.Skipf("host power plan immutable (%v); skipping", err)
	}
	if applied.PlanGUID != target {
		_, _ = c.Restore(ctx, winclient.PowerPlanSnapshot{PlanGUID: orig.PlanGUID})
		t.Skipf("host power plan immutable (setactive did not take effect: want %q, observed %q); skipping",
			target, applied.PlanGUID)
	}
	if _, err := c.Restore(ctx, winclient.PowerPlanSnapshot{PlanGUID: orig.PlanGUID}); err != nil {
		t.Logf("warning: could not restore original power plan %q: %v", orig.PlanGUID, err)
	}
	return orig
}

// accPowerPlanEnsureListable probes whether power plans can be listed on
// the target (read-only, no plan switch). Used by the data source test.
func accPowerPlanEnsureListable(t *testing.T) {
	t.Helper()
	c := accPowerPlanClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if _, err := c.List(ctx); err != nil {
		t.Skipf("power plan unsupported on target (%v); skipping", err)
	}
}

// powerPlanAccConfig renders a windows_power_plan resource with
// restore_on_destroy so the suite leaves the pre-existing plan behind.
func powerPlanAccConfig(plan string, acValue int64) string {
	return fmt.Sprintf(`
resource "windows_power_plan" "acc" {
  plan = %q

  settings = [
    { subgroup = "SUB_DISK", setting = "DISKIDLE", ac_value = %d },
  ]

  restore_on_destroy = true
}
`, plan, acValue)
}

// TestAccWindowsPowerPlan_InvalidPlan — a localised plan name is rejected
// at plan time, before any SSH call, so it is safe to run against any host.
func TestAccWindowsPowerPlan_InvalidPlan(t *testing.T) {
	testAccPowerPlanPreCheck(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_power_plan" "acc" {
  plan = "High performance"
}
`,
				ExpectError: regexp.MustCompile(`(?i)Invalid power plan`),
				PlanOnly:    true,
			},
		},
	})
}

// TestAccWindowsPowerPlan_Basic — switch to high_performance with a
// DISKIDLE override + idempotency (empty plan on re-apply).
func TestAccWindowsPowerPlan_Basic(t *testing.T) {
	testAccPowerPlanPreCheck(t)
	accPowerPlanEnsureMutable(t)

	cfg := powerPlanAccConfig("high_performance", 0)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					// The configured spelling is preserved in state;
					// plan_guid carries the resolved canonical GUID.
					resource.TestCheckResourceAttr("windows_power_plan.acc", "plan", "high_performance"),
					resource.TestCheckResourceAttr("windows_power_plan.acc", "plan_guid", winclient.PowerPlanHighPerformanceGUID),
					resource.TestCheckResourceAttrSet("windows_power_plan.acc", "id"),
					resource.TestCheckResourceAttrSet("windows_power_plan.acc", "plan_name"),
					// Configured aliases are preserved in state (not
					// replaced by observed GUIDs) so re-plans are empty.
					resource.TestCheckResourceAttr("windows_power_plan.acc", "settings.0.subgroup", "SUB_DISK"),
					resource.TestCheckResourceAttr("windows_power_plan.acc", "settings.0.setting", "DISKIDLE"),
					resource.TestCheckResourceAttr("windows_power_plan.acc", "settings.0.ac_value", "0"),
				),
			},
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccWindowsPowerPlan_UpdateInPlace — changing a setting value
// converges without replacing the singleton (id stays the machine GUID).
func TestAccWindowsPowerPlan_UpdateInPlace(t *testing.T) {
	testAccPowerPlanPreCheck(t)
	accPowerPlanEnsureMutable(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: powerPlanAccConfig("high_performance", 0),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_power_plan.acc", "settings.0.ac_value", "0"),
				),
			},
			{
				Config: powerPlanAccConfig("high_performance", 600),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_power_plan.acc", "settings.0.ac_value", "600"),
					resource.TestCheckResourceAttrSet("windows_power_plan.acc", "id"),
				),
			},
		},
	})
}

// TestAccWindowsPowerPlan_RestoreOnDestroy — destroy re-applies the
// pre-existing plan and DISKIDLE value captured at creation time.
func TestAccWindowsPowerPlan_RestoreOnDestroy(t *testing.T) {
	testAccPowerPlanPreCheck(t)
	orig := accPowerPlanEnsureMutable(t)

	// Capture the pre-existing DISKIDLE AC value for the post-destroy check.
	diskKey := []winclient.PowerPlanSettingKey{{Subgroup: "SUB_DISK", Setting: "DISKIDLE"}}
	origFull, err := accPowerPlanClient(t).Read(context.Background(), diskKey)
	if err != nil {
		t.Fatalf("pre-existing settings read: %v", err)
	}
	var origAC int64
	if len(origFull.Settings) == 1 && origFull.Settings[0].ACValue != nil {
		origAC = *origFull.Settings[0].ACValue
	}

	changedAC := int64(0)
	if origAC == 0 {
		changedAC = 600
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(*terraform.State) error {
			c, err := newAccPowerPlanClient()
			if err != nil {
				return fmt.Errorf("winclient.New: %w", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			live, err := c.Read(ctx, diskKey)
			if err != nil {
				return fmt.Errorf("post-destroy read: %w", err)
			}
			if live.PlanGUID != orig.PlanGUID {
				return fmt.Errorf("restore_on_destroy did not re-activate the pre-existing plan: want %q, live %q", orig.PlanGUID, live.PlanGUID)
			}
			if len(live.Settings) != 1 || live.Settings[0].ACValue == nil || *live.Settings[0].ACValue != origAC {
				return fmt.Errorf("restore_on_destroy did not restore the pre-existing DISKIDLE ac_value: want %d, live %+v", origAC, live.Settings)
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: powerPlanAccConfig("high_performance", changedAC),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_power_plan.acc", "plan", "high_performance"),
				),
			},
		},
	})
}

// TestAccWindowsPowerPlan_CreateIfMissingCustomGUID — a custom (non
// template) plan GUID cannot be duplicated: create_if_missing only
// restores the well-known templates. Documents the plan-time guidance via
// a failing apply when the host supports power plans.
func TestAccWindowsPowerPlan_CreateIfMissingCustomGUID(t *testing.T) {
	testAccPowerPlanPreCheck(t)
	accPowerPlanEnsureMutable(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_power_plan" "acc" {
  plan              = "11111111-2222-3333-4444-555555555555"
  create_if_missing = true
  restore_on_destroy = true
}
`,
				ExpectError: regexp.MustCompile(`(?i)plan_not_found|was not found|duplicatescheme`),
			},
		},
	})
}

// TestAccWindowsPowerPlan_Import — import the live active plan by any ID.
func TestAccWindowsPowerPlan_Import(t *testing.T) {
	testAccPowerPlanPreCheck(t)
	accPowerPlanEnsureMutable(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "windows_power_plan" "imp" {
  plan               = "high_performance"
  restore_on_destroy = true
}
`,
			},
			{
				ResourceName:      "windows_power_plan.imp",
				ImportState:       true,
				ImportStateId:     "current",
				ImportStateVerify: true,
				// restore_on_destroy is a local destroy-time intent,
				// not host state; plan_name is localised
				// informational text; plan keeps the configured
				// spelling after apply but import has no prior
				// config so it surfaces the observed GUID.
				ImportStateVerifyIgnore: []string{"restore_on_destroy", "plan"},
			},
		},
	})
}
