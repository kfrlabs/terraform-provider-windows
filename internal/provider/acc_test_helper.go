//go:build acceptance

// Package provider — shared plumbing for the acceptance test suite.
//
// This file only compiles under `-tags acceptance`, so the default unit-test
// build (`go test -short ./...`) is unaffected.
package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories provides the "windows" provider to every
// acceptance TestCase. Provider configuration (host / username / password)
// is resolved from the WINDOWS_* environment variables via
// winclient.ResolveFromEnv, so the HCL Config blocks need no explicit
// provider block.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"windows": providerserver.NewProtocol6WithError(New("test")()),
}
