//go:build acceptance

// Package provider — acceptance tests for windows_file_acl.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / a credential (see acc_test_helper.go)
//   - A Windows target reachable over SSH with Local Administrator rights.
//
// Every write is confined to C:\TF-Acc-FileACL so the suite is safe to re-run
// and leaves nothing behind.
//
// Two constraints of the disposable test container shape these tests:
//
//   - Its machine name is random and changes on every start, so no fixture
//     hardcodes a hostname. Identities are either well-known SIDs
//     (S-1-5-32-544, S-1-5-18) or bare local names, and assertions go through
//     identity_sid.
//   - Its SSH session holds a full admin token with SeTakeOwnershipPrivilege
//     enabled, so the privilege_not_held path is not reproducible here. It is
//     covered by a unit test instead.
package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

const (
	fileACLTestDir = `C:\TF-Acc-FileACL`

	// Well-known SIDs: stable on every Windows install, unlike any name that
	// would carry the container's random machine name.
	sidAdministrators = "S-1-5-32-544"
	sidUsers          = "S-1-5-32-545"
	identitySystem    = `NT AUTHORITY\SYSTEM`
)

func testAccFileACLPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// accFileACLRawClient builds a direct client for out-of-band manipulation,
// which is the only way to simulate drift and to provision fixtures such as an
// orphaned SID.
func accFileACLRawClient(t *testing.T) *winclient.Client {
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
	return c
}

func accFileACLClient(t *testing.T) winclient.FileACLClient {
	t.Helper()
	return winclient.NewFileACLClient(accFileACLRawClient(t))
}

// accFileACLRunPS runs a helper script on the target and fails the test on error.
func accFileACLRunPS(t *testing.T, script string) string {
	t.Helper()
	stdout, stderr, err := accFileACLRawClient(t).RunPowerShell(context.Background(),
		"$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n"+script)
	if err != nil {
		t.Fatalf("helper script failed: %v (stderr: %s)", err, stderr)
	}
	return strings.TrimSpace(stdout)
}

// accFileACLMakeDir creates a directory out of band, since the provider has no
// directory resource.
func accFileACLMakeDir(t *testing.T, path string) {
	t.Helper()
	accFileACLRunPS(t, fmt.Sprintf(
		"if (-not (Test-Path -LiteralPath %s)) { New-Item -ItemType Directory -Path %s | Out-Null }\n'ok'",
		psTestQuote(path), psTestQuote(path)))
}

func accFileACLMakeFile(t *testing.T, path string) {
	t.Helper()
	parent := path[:strings.LastIndex(path, `\`)]
	accFileACLMakeDir(t, parent)
	accFileACLRunPS(t, fmt.Sprintf("Set-Content -LiteralPath %s -Value 'acc' -Encoding utf8\n'ok'",
		psTestQuote(path)))
}

func accFileACLRemove(t *testing.T, path string) {
	t.Helper()
	accFileACLRunPS(t, fmt.Sprintf(
		"if (Test-Path -LiteralPath %s) { Remove-Item -LiteralPath %s -Recurse -Force }\n'ok'",
		psTestQuote(path), psTestQuote(path)))
}

// fileACLTestCaseDir gives each test case its own fixture directory. A shared
// one is not safe: two concurrent runs against the same target, which is easy to
// end up with when a test invocation is interrupted and left running, delete
// each other's files and produce failures that look exactly like product bugs.
func fileACLTestCaseDir(t *testing.T) string {
	t.Helper()
	return fileACLTestDir + `\` + t.Name()
}

// fileACLTestPath builds a fixture path inside the current test's directory.
func fileACLTestPath(t *testing.T, leaf string) string {
	t.Helper()
	return fileACLTestCaseDir(t) + `\` + leaf
}

// psTestQuote mirrors winclient.psQuote for the helper scripts above.
func psTestQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// testAccCheckFileACLDestroy asserts the descriptor was reset, not that the
// target was deleted: windows_file_acl never owns the target's existence.
func testAccCheckFileACLDestroy(s *terraform.State) error {
	var client winclient.FileACLClient
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "windows_file_acl" {
			continue
		}
		if client == nil {
			cfg := winclient.Config{Timeout: 60 * time.Second}
			winclient.ResolveFromEnv(&cfg)
			if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
				cfg.InsecureIgnoreHostKey = true
			}
			c, err := winclient.New(cfg)
			if err != nil {
				return err
			}
			client = winclient.NewFileACLClient(c)
		}
		path := rs.Primary.Attributes["path"]
		st, err := client.Read(context.Background(), path)
		if err != nil {
			return err
		}
		if st == nil {
			continue // the target itself was removed by another resource
		}
		if !st.InheritanceEnabled {
			return fmt.Errorf("%s is still protected from inheritance after destroy", path)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// TestAccWindowsFileACL_FileLifecycle covers create, idempotency, in-place
// update and import on a file.
func TestAccWindowsFileACL_FileLifecycle(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "lifecycle.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	cfg := func(rights string) string {
		return fmt.Sprintf(`
resource "windows_file_acl" "a" {
  path                = %q
  inheritance_enabled = false

  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
  access_rule {
    identity = %q
    rights   = [%q]
  }
}
`, path, identitySystem, sidAdministrators, rights)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileACLDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg("FullControl"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file_acl.a", "id", path),
					resource.TestCheckResourceAttr("windows_file_acl.a", "target_type", "file"),
					resource.TestCheckResourceAttr("windows_file_acl.a", "mode", "authoritative"),
					resource.TestCheckResourceAttr("windows_file_acl.a", "inheritance_enabled", "false"),
					resource.TestCheckResourceAttr("windows_file_acl.a", "access_rule.#", "2"),
					// Protection from inheritance shows up as PAI in the SDDL.
					resource.TestMatchResourceAttr("windows_file_acl.a", "sddl", regexp.MustCompile(`D:PA?I?`)),
					// With inheritance off and both rules declared, the effective
					// DACL is exactly those two entries.
					resource.TestCheckResourceAttr("windows_file_acl.a", "effective_access_rules.#", "2"),
					resource.TestCheckResourceAttr("windows_file_acl.a",
						"effective_access_rules.0.inherited", "false"),
					// A file gets no inheritance flags.
					resource.TestCheckResourceAttr("windows_file_acl.a",
						"effective_access_rules.0.inheritance", "none"),
				),
			},
			{
				// Re-applying the same configuration must be a no-op. This is the
				// step that catches a mask normalisation bug: if Read rewrote the
				// rights or the mask, the plan would never be empty.
				Config:   cfg("FullControl"),
				PlanOnly: true,
			},
			{
				Config: cfg("Modify"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file_acl.a", "access_rule.1.rights.#", "1"),
					resource.TestCheckTypeSetElemAttr("windows_file_acl.a", "access_rule.1.rights.*", "Modify"),
				),
			},
			{
				ResourceName:  "windows_file_acl.a",
				ImportState:   true,
				ImportStateId: path,
				// ImportStateVerify is off on purpose: import discovers the host's
				// entries, which carry canonical identities and a keyword
				// decomposition of each mask, so they cannot be string-equal to a
				// configuration that used a SID and an alias.
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("expected 1 imported state, got %d", len(states))
					}
					attrs := states[0].Attributes
					if attrs["path"] != path {
						return fmt.Errorf("imported path = %q, want %q", attrs["path"], path)
					}
					if attrs["mode"] != "authoritative" {
						return fmt.Errorf("imported mode = %q, want authoritative", attrs["mode"])
					}
					if attrs["target_type"] != "file" {
						return fmt.Errorf("imported target_type = %q, want file", attrs["target_type"])
					}
					// The two explicit entries must be adopted as blocks.
					if attrs["access_rule.#"] != "2" {
						return fmt.Errorf("imported access_rule.# = %q, want 2", attrs["access_rule.#"])
					}
					if attrs["sddl"] == "" {
						return fmt.Errorf("imported sddl is empty")
					}
					return nil
				},
			},
		},
	})
}

// TestAccWindowsFileACL_DirectoryInheritance covers a directory, where the
// inheritance and propagation flags actually mean something.
func TestAccWindowsFileACL_DirectoryInheritance(t *testing.T) {
	testAccFileACLPreCheck(t)
	dir := fileACLTestPath(t, "tree")
	accFileACLMakeDir(t, dir)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	cfg := fmt.Sprintf(`
resource "windows_file_acl" "d" {
  path = %q
  mode = "additive"

  access_rule {
    identity    = %q
    rights      = ["Modify"]
    inheritance = "container_object"
  }
  access_rule {
    identity    = %q
    rights      = ["ReadAndExecute"]
    inheritance = "container"
    propagation = "inherit_only"
  }
}
`, dir, sidAdministrators, sidUsers)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileACLDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file_acl.d", "target_type", "directory"),
					resource.TestCheckResourceAttr("windows_file_acl.d", "access_rule.0.inheritance", "container_object"),
					resource.TestCheckResourceAttr("windows_file_acl.d", "access_rule.1.propagation", "inherit_only"),
					func(s *terraform.State) error {
						// The flags must be observable on the host, not just in state.
						st, err := accFileACLClient(t).Read(context.Background(), dir)
						if err != nil {
							return err
						}
						for _, rule := range st.ExplicitRules() {
							if rule.IdentitySID == sidUsers {
								if rule.Inheritance != "container" || rule.Propagation != "inherit_only" {
									return fmt.Errorf("users entry has inheritance=%q propagation=%q, want container/inherit_only",
										rule.Inheritance, rule.Propagation)
								}
								return nil
							}
						}
						return fmt.Errorf("no explicit entry found for %s", sidUsers)
					},
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsFileACL_ModeSemantics is the difference between the two modes,
// exercised against a real out-of-band entry: additive leaves it alone,
// authoritative removes it.
func TestAccWindowsFileACL_ModeSemantics(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "modes.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	// An entry this configuration never declares.
	addForeignACE := func() {
		accFileACLRunPS(t, fmt.Sprintf(`
$acl = Get-Acl -LiteralPath %s
$sid = New-Object System.Security.Principal.SecurityIdentifier('%s')
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
  $sid, [System.Security.AccessControl.FileSystemRights]::Read,
  [System.Security.AccessControl.InheritanceFlags]::None,
  [System.Security.AccessControl.PropagationFlags]::None,
  [System.Security.AccessControl.AccessControlType]::Allow)))
Set-Acl -LiteralPath %s -AclObject $acl
'ok'`, psTestQuote(path), sidUsers, psTestQuote(path)))
	}

	foreignPresent := func(want bool) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			st, err := accFileACLClient(t).Read(context.Background(), path)
			if err != nil {
				return err
			}
			found := false
			for _, rule := range st.ExplicitRules() {
				if rule.IdentitySID == sidUsers {
					found = true
				}
			}
			if found != want {
				return fmt.Errorf("foreign entry present = %v, want %v", found, want)
			}
			return nil
		}
	}

	cfg := func(mode string) string {
		return fmt.Sprintf(`
resource "windows_file_acl" "m" {
  path = %q
  mode = %q

  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
}
`, path, mode, sidAdministrators)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileACLDestroy,
		Steps: []resource.TestStep{
			{
				PreConfig: addForeignACE,
				Config:    cfg("additive"),
				Check:     foreignPresent(true),
			},
			{
				// An unmanaged entry is not drift in additive mode.
				Config:   cfg("additive"),
				PlanOnly: true,
			},
			{
				Config: cfg("authoritative"),
				Check:  foreignPresent(false),
			},
			{
				Config:   cfg("authoritative"),
				PlanOnly: true,
			},
		},
	})
}

// TestAccWindowsFileACL_DriftDetection asserts an out-of-band change to the
// DACL is reported in authoritative mode.
func TestAccWindowsFileACL_DriftDetection(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "drift.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	cfg := fmt.Sprintf(`
resource "windows_file_acl" "drift" {
  path = %q

  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
}
`, path, sidAdministrators)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileACLDestroy,
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				// Someone widens the rights by hand: the next plan must not be empty.
				PreConfig: func() {
					accFileACLRunPS(t, fmt.Sprintf(`
$acl = Get-Acl -LiteralPath %s
$sid = New-Object System.Security.Principal.SecurityIdentifier('%s')
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
  $sid, [System.Security.AccessControl.FileSystemRights]::FullControl,
  [System.Security.AccessControl.InheritanceFlags]::None,
  [System.Security.AccessControl.PropagationFlags]::None,
  [System.Security.AccessControl.AccessControlType]::Allow)))
Set-Acl -LiteralPath %s -AclObject $acl
'ok'`, psTestQuote(path), sidUsers, psTestQuote(path)))
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Applying again must converge back.
				Config: cfg,
				Check: func(s *terraform.State) error {
					st, err := accFileACLClient(t).Read(context.Background(), path)
					if err != nil {
						return err
					}
					if len(st.ExplicitRules()) != 1 {
						return fmt.Errorf("got %d explicit entries, want 1 after reconvergence",
							len(st.ExplicitRules()))
					}
					return nil
				},
			},
		},
	})
}

// TestAccWindowsFileACL_WithWindowsFile is the cross-resource invariant: a
// content update by windows_file must not disturb the descriptor managed here
// (windows_file EC-15).
func TestAccWindowsFileACL_WithWindowsFile(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "managed.conf")
	accFileACLMakeDir(t, fileACLTestCaseDir(t))
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	cfg := func(content string) string {
		return fmt.Sprintf(`
resource "windows_file" "f" {
  path    = %q
  content = %q
}

resource "windows_file_acl" "a" {
  path                = windows_file.f.path
  inheritance_enabled = false

  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
}
`, path, content, identitySystem, sidAdministrators)
	}

	var sddlBefore string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("first"),
				Check: func(s *terraform.State) error {
					st, err := accFileACLClient(t).Read(context.Background(), path)
					if err != nil {
						return err
					}
					sddlBefore = st.SDDL
					if sddlBefore == "" {
						return fmt.Errorf("no SDDL observed")
					}
					return nil
				},
			},
			{
				// Only the content changes. windows_file rewrites the file through
				// File.Replace precisely so the descriptor survives; assert it did.
				Config: cfg("second"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file.f", "content", "second"),
					func(s *terraform.State) error {
						st, err := accFileACLClient(t).Read(context.Background(), path)
						if err != nil {
							return err
						}
						if st.SDDL != sddlBefore {
							return fmt.Errorf("a content update altered the security descriptor:\nbefore %s\nafter  %s",
								sddlBefore, st.SDDL)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestAccWindowsFileACL_OrphanedSID covers an ACE whose account was deleted
// after the fact. The SID becomes unresolvable and must be preserved in
// additive mode and removed in authoritative mode, never crash the read.
func TestAccWindowsFileACL_OrphanedSID(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "orphan.conf")
	accFileACLMakeFile(t, path)
	t.Cleanup(func() {
		accFileACLRunPS(t, "if (Get-LocalUser -Name tfaclorphan -ErrorAction SilentlyContinue) "+
			"{ Remove-LocalUser -Name tfaclorphan }\n'ok'")
		accFileACLRemove(t, fileACLTestCaseDir(t))
	})

	// Provision the orphan: create a local account, grant it an entry, delete it.
	orphanSID := accFileACLRunPS(t, fmt.Sprintf(`
$pw = ConvertTo-SecureString 'Tf-Acl-0rph4n!' -AsPlainText -Force
if (Get-LocalUser -Name tfaclorphan -ErrorAction SilentlyContinue) { Remove-LocalUser -Name tfaclorphan }
New-LocalUser -Name tfaclorphan -Password $pw -PasswordNeverExpires | Out-Null
$sid = (Get-LocalUser -Name tfaclorphan).SID.Value
$acl = Get-Acl -LiteralPath %s
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
  (New-Object System.Security.Principal.SecurityIdentifier($sid)),
  [System.Security.AccessControl.FileSystemRights]::Read,
  [System.Security.AccessControl.InheritanceFlags]::None,
  [System.Security.AccessControl.PropagationFlags]::None,
  [System.Security.AccessControl.AccessControlType]::Allow)))
Set-Acl -LiteralPath %s -AclObject $acl
Remove-LocalUser -Name tfaclorphan
$sid`, psTestQuote(path), psTestQuote(path)))

	if !strings.HasPrefix(orphanSID, "S-1-") {
		t.Fatalf("could not provision the orphaned SID, got %q", orphanSID)
	}

	orphanPresent := func(want bool) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			st, err := accFileACLClient(t).Read(context.Background(), path)
			if err != nil {
				return err
			}
			found := false
			for _, rule := range st.ExplicitRules() {
				if rule.IdentitySID == orphanSID {
					found = true
					// An unresolvable SID reads back as its own display name.
					if rule.Identity != orphanSID {
						return fmt.Errorf("orphaned entry identity = %q, want the raw SID %q",
							rule.Identity, orphanSID)
					}
				}
			}
			if found != want {
				return fmt.Errorf("orphaned entry present = %v, want %v", found, want)
			}
			return nil
		}
	}

	cfg := func(mode string) string {
		return fmt.Sprintf(`
resource "windows_file_acl" "o" {
  path = %q
  mode = %q

  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
}
`, path, mode, sidAdministrators)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileACLDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg("additive"),
				Check:  orphanPresent(true),
			},
			{
				Config: cfg("authoritative"),
				Check:  orphanPresent(false),
			},
		},
	})
}

// TestAccWindowsFileACL_Owner covers ownership, which the test container can
// exercise because its SSH session holds SeTakeOwnershipPrivilege.
func TestAccWindowsFileACL_Owner(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "owner.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	cfg := fmt.Sprintf(`
resource "windows_file_acl" "o" {
  path  = %q
  owner = %q

  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
}
`, path, sidAdministrators, sidAdministrators)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileACLDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file_acl.o", "owner_sid", sidAdministrators),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

func TestAccWindowsFileACL_ErrorMissingTarget(t *testing.T) {
	testAccFileACLPreCheck(t)
	missing := fileACLTestPath(t, "does-not-exist.conf")
	accFileACLMakeDir(t, fileACLTestCaseDir(t))
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "windows_file_acl" "missing" {
  path = %q
  access_rule {
    identity = %q
    rights   = ["FullControl"]
  }
}
`, missing, sidAdministrators),
			// Deliberately short patterns: Terraform hard-wraps diagnostics at a
			// width that depends on the length of the interpolated path, so a
			// multi-word pattern breaks as soon as a fixture is renamed.
			ExpectError: regexp.MustCompile(`(?s)target not found.*never creates`),
		}},
	})
}

func TestAccWindowsFileACL_ErrorUnknownIdentity(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "bad-identity.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "windows_file_acl" "bad" {
  path = %q
  access_rule {
    identity = "no-such-account-tfacc"
    rights   = ["Read"]
  }
}
`, path),
			ExpectError: regexp.MustCompile(`unknown identity`),
		}},
	})
}

// TestAccWindowsFileACL_ErrorInheritanceOnFile covers the type conflict: an
// inheritance flag is meaningless on a file, and writing it silently would
// mislead the operator.
func TestAccWindowsFileACL_ErrorInheritanceOnFile(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "flags.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "windows_file_acl" "flags" {
  path = %q
  access_rule {
    identity    = %q
    rights      = ["Modify"]
    inheritance = "container_object"
  }
}
`, path, sidAdministrators),
			ExpectError: regexp.MustCompile(`only valid on a directory`),
		}},
	})
}

// TestAccWindowsFileACL_ErrorEmptyDACLGuard asserts the lockout guard fires at
// plan time, before anything is written.
func TestAccWindowsFileACL_ErrorEmptyDACLGuard(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "lockout.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "windows_file_acl" "lockout" {
  path                = %q
  inheritance_enabled = false

  access_rule {
    identity = %q
    rights   = ["Write"]
    type     = "deny"
  }
}
`, path, sidUsers),
			ExpectError: regexp.MustCompile(`(?s)empty effective DACL`),
		}},
	})
}

func TestAccWindowsFileACL_ErrorAuthoritativeWithoutRules(t *testing.T) {
	testAccFileACLPreCheck(t)
	path := fileACLTestPath(t, "norules.conf")
	accFileACLMakeFile(t, path)
	dirForCleanup := fileACLTestCaseDir(t)
	t.Cleanup(func() { accFileACLRemove(t, dirForCleanup) })

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config: fmt.Sprintf(`
resource "windows_file_acl" "norules" {
  path = %q
}
`, path),
			ExpectError: regexp.MustCompile(`(?s)authoritative mode requires at least one access_rule`),
		}},
	})
}
