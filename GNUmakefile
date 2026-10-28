# GNUmakefile for terraform-provider-windows.
#
# Single makefile for this repository (GNU make prefers GNUmakefile over
# Makefile, so keeping both meant edits to Makefile were silently ignored).
# NAME and BINARY only feed the clean target; the provider is versioned by
# git tags via GoReleaser, not by a make variable.

NAME ?= windows
BINARY = terraform-provider-$(NAME)

.PHONY: build test testacc lint fmt docs clean

build:
	go install ./...

test:
	go test -short ./... -timeout 120s

# Full local acceptance run against a Windows target (see CLAUDE.md). The
# 120m budget covers every family back to back; CI instead shards the suite
# (.github/workflows/testacc-windows.yml) with a 45m timeout per shard.
testacc:
	TF_ACC=1 go test -tags acceptance ./... -v -timeout 120m

lint:
	golangci-lint run

fmt:
	gofmt -s -w .
	@command -v terraform >/dev/null 2>&1 && terraform fmt -recursive examples/ || echo "terraform not installed, skipping examples/ fmt"

docs:
	go generate ./...

clean:
	rm -f $(BINARY)
