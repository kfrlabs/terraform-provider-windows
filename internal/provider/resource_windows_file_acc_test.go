//go:build acceptance

// Package provider — acceptance tests for windows_file.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME / a credential (see acc_test_helper.go)
//   - A Windows target reachable over SSH with Local Administrator rights.
//
// Every write is confined to C:\TF-Acc-File so the suite is safe to re-run and
// leaves nothing behind.
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

const fileTestDir = `C:\TF-Acc-File`

func testAccFilePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// accFileClient builds a direct winclient for out-of-band manipulation, which
// is the only way to simulate drift (EC-5) and disappearance (EC-4).
//
// ResolveFromEnv is intentional here: the public-key CI leg clears
// WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH instead. Keeping a
// password-only config in this helper makes the resource tests fail during
// their cleanup even though the provider itself authenticated successfully.
func accFileClient(t *testing.T) winclient.FileClient {
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
	return winclient.NewFileClient(c)
}

// testAccCheckFileDestroy asserts every managed file is gone after destroy.
func testAccCheckFileDestroy(s *terraform.State) error {
	var fc winclient.FileClient
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "windows_file" {
			continue
		}
		if fc == nil {
			cfg := winclient.Config{Timeout: 60 * time.Second}
			winclient.ResolveFromEnv(&cfg)
			if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
				cfg.InsecureIgnoreHostKey = true
			}
			c, err := winclient.New(cfg)
			if err != nil {
				return err
			}
			fc = winclient.NewFileClient(c)
		}
		st, err := fc.Read(context.Background(), rs.Primary.Attributes["path"])
		if err != nil {
			return err
		}
		if st != nil {
			return fmt.Errorf("file %s still exists after destroy", rs.Primary.Attributes["path"])
		}
	}
	return nil
}

// TestAccWindowsFile_ContentLifecycle — create, idempotency, in-place update
// and import with content read-back (import decision (b)).
func TestAccWindowsFile_ContentLifecycle(t *testing.T) {
	testAccFilePreCheck(t)
	path := fileTestDir + `\lifecycle.txt`

	cfg := func(content string) string {
		return fmt.Sprintf(`
resource "windows_file" "f" {
  path    = %q
  content = %q
}
`, path, content)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg("hello"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file.f", "size_bytes", "5"),
					resource.TestCheckResourceAttr("windows_file.f", "id", path),
					resource.TestCheckResourceAttr("windows_file.f", "content_sha256",
						"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
					resource.TestCheckResourceAttr("windows_file.f", "encoding", "utf8"),
				),
			},
			{
				// EC: a re-apply of the same config must be a no-op.
				Config:   cfg("hello"),
				PlanOnly: true,
			},
			{
				// In-place update: only `path` is ForceNew.
				Config: cfg("hello world"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file.f", "size_bytes", "11"),
				),
			},
			{
				// EC-18: below 1 MiB the content is read back, so the state
				// round-trips and the next plan is clean.
				ResourceName:            "windows_file.f",
				ImportState:             true,
				ImportStateId:           path,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
		},
	})
}

// TestAccWindowsFile_EmptyAndBinary — EC-8 (0-byte file) and base64 content.
func TestAccWindowsFile_EmptyAndBinary(t *testing.T) {
	testAccFilePreCheck(t)

	cfg := fmt.Sprintf(`
resource "windows_file" "empty" {
  path    = %q
  content = ""
}

resource "windows_file" "bin" {
  path           = %q
  content_base64 = "AAECA/8="
}
`, fileTestDir+`\empty.txt`, fileTestDir+`\blob.bin`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileDestroy,
		Steps: []resource.TestStep{{
			Config: cfg,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("windows_file.empty", "size_bytes", "0"),
				resource.TestCheckResourceAttr("windows_file.bin", "size_bytes", "5"),
			),
		}},
	})
}

// TestAccWindowsFile_Encodings — EC-9 / EC-10: byte-exact encodings, no
// line-ending rewriting.
func TestAccWindowsFile_Encodings(t *testing.T) {
	testAccFilePreCheck(t)

	cfg := fmt.Sprintf(`
resource "windows_file" "bom" {
  path     = %q
  content  = "ab"
  encoding = "utf8bom"
}

resource "windows_file" "utf16" {
  path       = %q
  content    = "ab"
  encoding   = "utf16le"
  depends_on = [windows_file.bom]
}

resource "windows_file" "crlf" {
  path       = %q
  content    = "a\r\nb"
  depends_on = [windows_file.utf16]
}

resource "windows_file" "accents" {
  path       = %q
  content    = "caf\u00e9"
  depends_on = [windows_file.crlf]
}
`, fileTestDir+`\bom.txt`, fileTestDir+`\utf16.txt`, fileTestDir+`\crlf.txt`, fileTestDir+`\accents.txt`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileDestroy,
		Steps: []resource.TestStep{{
			Config: cfg,
			Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("windows_file.bom", "size_bytes", "5"),   // BOM + 2
				resource.TestCheckResourceAttr("windows_file.utf16", "size_bytes", "4"), // 2 units
				resource.TestCheckResourceAttr("windows_file.crlf", "size_bytes", "4"),  // CRLF kept
				resource.TestCheckResourceAttr("windows_file.accents", "size_bytes", "5"),
			),
		}},
	})
}

// TestAccWindowsFile_Attributes — EC-6: a readonly file can still be updated
// and destroyed.
func TestAccWindowsFile_Attributes(t *testing.T) {
	testAccFilePreCheck(t)
	path := fileTestDir + `\readonly.txt`

	cfg := func(content string) string {
		return fmt.Sprintf(`
resource "windows_file" "ro" {
  path       = %q
  content    = %q
  attributes = ["hidden", "readonly"]
}
`, path, content)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg("v1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_file.ro", "attributes.#", "2"),
					resource.TestCheckResourceAttr("windows_file.ro", "attributes.0", "hidden"),
					resource.TestCheckResourceAttr("windows_file.ro", "attributes.1", "readonly"),
				),
			},
			{
				// Updating through the readonly flag is the point of this test.
				Config: cfg("v2"),
				Check:  resource.TestCheckResourceAttr("windows_file.ro", "size_bytes", "2"),
			},
		},
	})
}

// TestAccWindowsFile_WriteOnlyContent — EC-19: the secret never lands in state,
// and only a version bump rewrites the file.
func TestAccWindowsFile_WriteOnlyContent(t *testing.T) {
	testAccFilePreCheck(t)
	path := fileTestDir + `\secret.txt`

	cfg := func(secret, version string) string {
		return fmt.Sprintf(`
resource "windows_file" "wo" {
  path               = %q
  content_wo         = %q
  content_wo_version = %q
}
`, path, secret, version)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg("p@ssw0rd", "1"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckNoResourceAttr("windows_file.wo", "content_wo"),
					resource.TestCheckResourceAttr("windows_file.wo", "size_bytes", "8"),
					resource.TestCheckResourceAttr("windows_file.wo", "content_wo_version", "1"),
				),
			},
			{
				// Same version: no rewrite, even though the value changed.
				Config:   cfg("different", "1"),
				PlanOnly: true,
			},
			{
				// Bumped version: the file is rewritten.
				Config: cfg("muchlongersecret", "2"),
				Check:  resource.TestCheckResourceAttr("windows_file.wo", "size_bytes", "16"),
			},
		},
	})
}

// TestAccWindowsFile_DriftAndDisappearance — EC-5 and EC-4.
func TestAccWindowsFile_DriftAndDisappearance(t *testing.T) {
	testAccFilePreCheck(t)
	path := fileTestDir + `\drift.txt`

	cfg := fmt.Sprintf(`
resource "windows_file" "d" {
  path    = %q
  content = "managed"
}
`, path)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckFileDestroy,
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				// EC-5: content changed behind Terraform's back.
				PreConfig: func() {
					fc := accFileClient(t)
					if _, err := fc.Set(context.Background(), winclient.FileInput{
						Path:          path,
						ContentBase64: "dGFtcGVyZWQ=", // "tampered"
						Overwrite:     true,
						CreateParents: true,
					}); err != nil {
						t.Fatalf("out-of-band write: %v", err)
					}
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{Config: cfg},
			{
				// EC-4: file removed behind Terraform's back.
				PreConfig: func() {
					fc := accFileClient(t)
					if err := fc.Delete(context.Background(), path); err != nil {
						t.Fatalf("out-of-band delete: %v", err)
					}
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{Config: cfg},
		},
	})
}

// TestAccWindowsFile_CreateParentsFalse — EC-1.
func TestAccWindowsFile_CreateParentsFalse(t *testing.T) {
	testAccFilePreCheck(t)

	cfg := fmt.Sprintf(`
resource "windows_file" "orphan" {
  path           = %q
  content        = "x"
  create_parents = false
}
`, fileTestDir+`\nope\deeper\file.txt`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexpMustCompile(`parent directory`),
		}},
	})
}

// TestAccWindowsFile_DirectoryConflict — EC-2.
func TestAccWindowsFile_DirectoryConflict(t *testing.T) {
	testAccFilePreCheck(t)

	cfg := `
resource "windows_file" "conflict" {
  path    = "C:\\Windows"
  content = "x"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{{
			Config:      cfg,
			ExpectError: regexpMustCompile(`directory`),
		}},
	})
}

// TestAccWindowsFile_OverwriteFalse — EC-3.
func TestAccWindowsFile_OverwriteFalse(t *testing.T) {
	testAccFilePreCheck(t)
	path := fileTestDir + `\guarded.txt`

	first := fmt.Sprintf(`
resource "windows_file" "first" {
  path    = %q
  content = "original"
}
`, path)

	second := first + fmt.Sprintf(`
resource "windows_file" "second" {
  path       = %q
  content    = "replacement"
  overwrite  = false
  depends_on = [windows_file.first]
}
`, path)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: first},
			{
				Config:      second,
				ExpectError: regexpMustCompile(`already exists`),
			},
		},
	})
}

// regexpMustCompile keeps the ExpectError call sites readable.
func regexpMustCompile(s string) *regexp.Regexp { return regexp.MustCompile(s) }
