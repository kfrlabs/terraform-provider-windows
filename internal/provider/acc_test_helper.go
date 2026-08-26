//go:build acceptance

// Package provider — shared plumbing for the acceptance test suite.
//
// This file only compiles under `-tags acceptance`, so the default unit-test
// build (`go test -short ./...`) is unaffected.
package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccRequireEnv skips unless the environment can reach a Windows host.
//
// It requires a target and a user, plus **at least one credential** — not
// WINDOWS_PASSWORD specifically. Every per-resource pre-check used to demand
// the password, which silently gutted the public-key leg of the CI matrix: with
// WINDOWS_PASSWORD deliberately cleared to prove the key alone works, 69 of the
// 85 tests in the `rest` shard skipped, and the seven that were failing there
// were invisible. Coupling the suite to one auth method means the method the
// provider now recommends is the one it does not test.
//
// Keep this the single place that decides: a per-file copy will drift.
func testAccRequireEnv(t *testing.T) {
	t.Helper()

	for _, k := range []string{"WINDOWS_HOST", "WINDOWS_USERNAME"} {
		if os.Getenv(k) == "" {
			t.Skipf("env %s not set; skipping acceptance test", k)
		}
	}

	// Mirrors winclient.buildAuthMethods: any one of these is enough to
	// authenticate, so any one of them is enough to run the suite.
	credentials := []string{
		"WINDOWS_PASSWORD",
		"WINDOWS_PRIVATE_KEY",
		"WINDOWS_PRIVATE_KEY_PATH",
	}
	for _, k := range credentials {
		if os.Getenv(k) != "" {
			return
		}
	}
	if os.Getenv("WINDOWS_USE_AGENT") == "true" || os.Getenv("SSH_AUTH_SOCK") != "" {
		return
	}

	t.Skipf("no credential set (one of %v, WINDOWS_USE_AGENT or SSH_AUTH_SOCK); skipping acceptance test", credentials)
}

// testAccProtoV6ProviderFactories provides the "windows" provider to every
// acceptance TestCase. Provider configuration (host / username / password)
// is resolved from the WINDOWS_* environment variables via
// winclient.ResolveFromEnv, so the HCL Config blocks need no explicit
// provider block.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"windows": providerserver.NewProtocol6WithError(New("test")()),
}
