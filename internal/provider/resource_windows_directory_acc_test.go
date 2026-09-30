//go:build acceptance

// Package provider acceptance tests for windows_directory.
package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/kfrlabs/terraform-provider-windows/internal/winclient"
)

const directoryTestRoot = `C:\TF-Acc-Directory`

func testAccDirectoryPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

func testAccDirectoryDestroy(s *terraform.State) error {
	cfg := winclient.Config{}
	winclient.ResolveFromEnv(&cfg)
	if cfg.KnownHostsPath == "" && cfg.HostKey == "" {
		cfg.InsecureIgnoreHostKey = true
	}
	c, err := winclient.New(cfg)
	if err != nil {
		return err
	}
	dc := winclient.NewDirectoryClient(c)
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "windows_directory" {
			continue
		}
		st, err := dc.Read(context.Background(), rs.Primary.Attributes["path"])
		if err != nil {
			return err
		}
		if st != nil {
			return fmt.Errorf("directory %s still exists after destroy", rs.Primary.Attributes["path"])
		}
	}
	return nil
}

func TestAccWindowsDirectoryLifecycle(t *testing.T) {
	testAccDirectoryPreCheck(t)
	path := directoryTestRoot + `\nested\application`
	config := func(attrs string) string {
		return fmt.Sprintf(`
resource "windows_directory" "app" {
  path            = %q
  create_parents  = true
  attributes      = %s
  recursive_delete = true
}
`, path, attrs)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccDirectoryDestroy,
		Steps: []resource.TestStep{
			{Config: config(`["hidden"]`), Check: resource.ComposeTestCheckFunc(
				resource.TestCheckResourceAttr("windows_directory.app", "id", path),
				resource.TestCheckResourceAttr("windows_directory.app", "attributes.0", "hidden"),
			)},
			{Config: config(`["archive", "hidden"]`), Check: resource.TestCheckResourceAttr("windows_directory.app", "attributes.#", "2")},
			{ResourceName: "windows_directory.app", ImportState: true, ImportStateId: path, ImportStateVerify: true},
		},
	})
}

func TestAccWindowsDirectoryNonRecursiveDeleteRefusesContents(t *testing.T) {
	testAccDirectoryPreCheck(t)
	path := directoryTestRoot + `\nonempty`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: fmt.Sprintf(`resource "windows_directory" "d" {
  path = %q
  recursive_delete = false
}
`, path)},
			{Config: fmt.Sprintf(`resource "windows_directory" "d" {
  path = %q
  recursive_delete = false
}
resource "windows_file" "child" {
  path = %q
  content = "owned by the test"
  depends_on = [windows_directory.d]
}
`, path, path+`\child.txt`)},
		},
	})
}
