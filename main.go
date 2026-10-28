// Package main is the entry point for the terraform-provider-windows plugin.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/kfrlabs/terraform-provider-windows/internal/provider"
)

// providerAddress is the Terraform Registry address of this provider.
const providerAddress = "registry.terraform.io/kfrlabs/windows"

// version is injected at build time via -ldflags.
var version = "dev"

// commit is the git SHA injected at build time via -ldflags
// (-X main.commit=... in .goreleaser.yml); "none" for local builds. It is
// reported on the startup log line so a running binary can be traced back
// to the commit that produced it.
var commit = "none"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	log.Printf("%s %s (commit %s)", providerAddress, version, commit)

	opts := providerserver.ServeOpts{
		Address: providerAddress,
		Debug:   debug,
	}

	if err := providerserver.Serve(context.Background(), provider.New(version), opts); err != nil {
		log.Fatal(err.Error())
	}
}
