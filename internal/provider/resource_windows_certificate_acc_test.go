//go:build acceptance

// Package provider — acceptance tests for windows_certificate.
//
// Requires:
//   - TF_ACC=1
//   - WINDOWS_HOST / WINDOWS_USERNAME + at least one credential env var
//   - A Windows target with SSH enabled (the tests write to
//     Cert:\LocalMachine\My, so the SSH user needs local elevation).
//
// SAFETY: every test mints its own throwaway self-signed certificate on the
// target (New-SelfSignedCertificate with a unique tfacc DNS name), exports
// it (public DER for PEM tests, PFX bundle for PFX tests) and removes the
// minted entry immediately — no committed key material, no shared store
// entries, and CheckDestroy asserts the resource entry is gone afterwards.
package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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

func testAccCertificatePreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	testAccRequireEnv(t)
}

// accCertificateClient builds a direct winclient for minting fixtures and
// asserting destroy. ResolveFromEnv is intentional here: the public-key CI
// leg clears WINDOWS_PASSWORD and provides WINDOWS_PRIVATE_KEY_PATH instead.
func accCertificateClient(t *testing.T) (*winclient.Client, *winclient.CertificateClientImpl) {
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
	return c, winclient.NewCertificateClient(c)
}

// testAccCertificateMinted carries the exported material of a throwaway
// self-signed certificate minted on the target.
type testAccCertificateMinted struct {
	// PEM holds the public certificate in PEM form (empty for PFX mints).
	PEM string
	// Bundle holds the base64 PFX for PFX mints (empty for PEM mints).
	Bundle string
	// Password is the PFX password (empty for PEM mints).
	Password string
	// Subject is the distinguished name, Thumbprint the SHA-1 thumbprint.
	Subject    string
	Thumbprint string
	// DNSName is the unique tfacc DNS name minted.
	DNSName string
}

// testAccCertificateMint mints a throwaway self-signed certificate on the
// target with a unique DNS name and exports it: public DER (converted to PEM
// provider-side) for format "pem", PFX bundle for format "pfx". With keep
// false the minted store entry is removed immediately and the material feeds
// a resource; with keep true the entry stays for data source lookups and is
// removed in t.Cleanup.
func testAccCertificateMint(t *testing.T, format string, keep bool) testAccCertificateMinted {
	t.Helper()
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("rand: %v", err)
	}
	dns := fmt.Sprintf("tfacc-%s.example.com", hex.EncodeToString(suffix))
	password := ""
	if format == "pfx" {
		pw := make([]byte, 12)
		if _, err := rand.Read(pw); err != nil {
			t.Fatalf("rand: %v", err)
		}
		password = "TFacc-" + hex.EncodeToString(pw)
	}

	c, _ := accCertificateClient(t)
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	exportFlag := ""
	extraExport := ""
	if format == "pfx" {
		exportFlag = " -KeyExportPolicy Exportable"
		extraExport = fmt.Sprintf(`
$pw = ConvertTo-SecureString -String %s -AsPlainText -Force
Export-PfxCertificate -Cert $certPath -FilePath $tmpFile -Password $pw -Force | Out-Null`, "'"+password+"'")
	} else {
		extraExport = `Export-Certificate -Cert $certPath -FilePath $tmpFile -Force | Out-Null`
	}
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$dns = '%s'
$cert = New-SelfSignedCertificate -DnsName $dns -CertStoreLocation 'Cert:\LocalMachine\My'%s -NotAfter (Get-Date).AddDays(30)
$certPath = ('Cert:\LocalMachine\My\' + $cert.Thumbprint)
$tmpFile = Join-Path $env:TEMP ('tfacc-' + $cert.Thumbprint + '.bin')
try {
%s
  $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($tmpFile))
  [Console]::Out.WriteLine($cert.Thumbprint)
  [Console]::Out.WriteLine([string]$cert.Subject)
  [Console]::Out.WriteLine($b64)
} finally {
  if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
}
`, dns, exportFlag, extraExport)
	stdout, stderr, err := c.RunPowerShell(ctx, script)
	if err != nil {
		t.Fatalf("mint self-signed certificate: %v (stderr: %s)", err, stderr)
	}
	lines := []string{}
	for _, l := range strings.Split(strings.ReplaceAll(stdout, "\r\n", "\n"), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			lines = append(lines, s)
		}
	}
	if len(lines) < 3 {
		t.Fatalf("mint output has %d lines, want thumbprint/subject/base64: %q", len(lines), stdout)
	}
	thumb, subject, b64 := lines[len(lines)-3], lines[len(lines)-2], lines[len(lines)-1]

	remove := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		rm := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$p = 'Cert:\LocalMachine\My\%s'
if (Test-Path $p) { Remove-Item $p -Force }`, thumb)
		if _, _, err := c.RunPowerShell(ctx, rm); err != nil {
			t.Logf("cleanup of minted certificate %s: %v", thumb, err)
		}
	}
	if keep {
		t.Cleanup(remove)
	} else {
		remove()
	}

	minted := testAccCertificateMinted{Subject: subject, Thumbprint: thumb, DNSName: dns}
	if format == "pfx" {
		minted.Bundle = b64
		minted.Password = password
		return minted
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		t.Fatalf("decode exported certificate: %v", err)
	}
	minted.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return minted
}

// testAccCertificatePEMFixture renders a windows_certificate resource fed by
// freshly minted PEM material.
func testAccCertificatePEMFixture(pemText, extra string) string {
	return fmt.Sprintf(`
resource "windows_certificate" "test" {
  certificate_pem = %q
%s
}
`, pemText, extra)
}

// testAccCertificatePFXFixture renders a windows_certificate resource fed by
// a freshly minted PFX bundle.
func testAccCertificatePFXFixture(bundle, password, extra string) string {
	return fmt.Sprintf(`
resource "windows_certificate" "test" {
  pfx_base64_wo   = %q
  pfx_password_wo = %q
  pfx_wo_version  = 1
%s
}
`, bundle, password, extra)
}

// testAccCheckWindowsCertificateDestroy asserts every managed certificate is
// gone from the store.
func testAccCheckWindowsCertificateDestroy(s *terraform.State) error {
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
	certs := winclient.NewCertificateClient(c)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "windows_certificate" {
			continue
		}
		parts := strings.Split(rs.Primary.ID, "/")
		if len(parts) != 3 {
			return fmt.Errorf("bad ID %q", rs.Primary.ID)
		}
		got, err := certs.Read(ctx, parts[0], parts[1], parts[2])
		if err != nil {
			return fmt.Errorf("destroy check for %s: %w", rs.Primary.ID, err)
		}
		if got != nil {
			return fmt.Errorf("certificate %s still present after destroy", rs.Primary.ID)
		}
	}
	return nil
}

// TestAccWindowsCertificate_PEM — create from PEM, friendly-name update,
// import round-trip; the fixture cert carries no private key.
func TestAccWindowsCertificate_PEM(t *testing.T) {
	testAccCertificatePreCheck(t)
	minted := testAccCertificateMint(t, "pem", false)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckWindowsCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccCertificatePEMFixture(minted.PEM, `  friendly_name = "tf-acc-cert"
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_certificate.test", "store_location", "LocalMachine"),
					resource.TestCheckResourceAttr("windows_certificate.test", "store_name", "My"),
					resource.TestCheckResourceAttr("windows_certificate.test", "friendly_name", "tf-acc-cert"),
					resource.TestCheckResourceAttr("windows_certificate.test", "has_private_key", "false"),
					resource.TestCheckResourceAttr("windows_certificate.test", "thumbprint", minted.Thumbprint),
					resource.TestCheckResourceAttr("windows_certificate.test", "subject", minted.Subject),
					resource.TestCheckResourceAttr("windows_certificate.test", "dns_names.0", minted.DNSName),
					resource.TestCheckResourceAttrSet("windows_certificate.test", "thumbprint_sha256"),
					resource.TestCheckResourceAttrSet("windows_certificate.test", "serial_number"),
					resource.TestCheckResourceAttrSet("windows_certificate.test", "not_before"),
					resource.TestCheckResourceAttrSet("windows_certificate.test", "not_after"),
					resource.TestCheckResourceAttrSet("windows_certificate.test", "issuer"),
				),
			},
			{
				// In-place update: only the friendly name changes.
				Config: testAccCertificatePEMFixture(minted.PEM, `  friendly_name = "tf-acc-cert-renamed"
`),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_certificate.test", "friendly_name", "tf-acc-cert-renamed"),
					resource.TestCheckResourceAttr("windows_certificate.test", "thumbprint", minted.Thumbprint),
				),
			},
			{
				// Import round-trip; the PEM and friendly name verify in place.
				ResourceName:      "windows_certificate.test",
				ImportState:       true,
				ImportStateId:     "LocalMachine/My/" + minted.Thumbprint,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccWindowsCertificate_PFX — create from a PFX bundle with an
// exportable private key, then import (which records pfx_wo_version = 1).
func TestAccWindowsCertificate_PFX(t *testing.T) {
	testAccCertificatePreCheck(t)
	minted := testAccCertificateMint(t, "pfx", false)

	cfg := testAccCertificatePFXFixture(minted.Bundle, minted.Password, `  exportable    = true
  friendly_name = "tf-acc-pfx"
`)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckWindowsCertificateDestroy,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("windows_certificate.test", "has_private_key", "true"),
					resource.TestCheckResourceAttr("windows_certificate.test", "thumbprint", minted.Thumbprint),
					resource.TestCheckResourceAttr("windows_certificate.test", "subject", minted.Subject),
					resource.TestCheckResourceAttr("windows_certificate.test", "pfx_wo_version", "1"),
				),
			},
			{
				// Import round-trip: the keyed certificate imports with
				// pfx_wo_version = 1, matching the configuration.
				// Exportability is not observable on the host, so the
				// imported exportable = false is ignored.
				ResourceName:      "windows_certificate.test",
				ImportState:       true,
				ImportStateId:     "LocalMachine/My/" + minted.Thumbprint,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"exportable",
				},
			},
		},
	})
}

// TestAccWindowsCertificate_CurrentUserRootRefused pins the plan-time
// refusal of CurrentUser trusted-root stores end to end.
func TestAccWindowsCertificate_CurrentUserRootRefused(t *testing.T) {
	testAccCertificatePreCheck(t)
	minted := testAccCertificateMint(t, "pem", false)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "windows_certificate" "refused" {
  store_location = "CurrentUser"
  store_name     = "Root"
  certificate_pem = %q
}
`, minted.PEM),
				ExpectError: regexp.MustCompile(`trust anchors`),
			},
		},
	})
}
