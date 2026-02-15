.PHONY: help build install test testacc clean fmt lint docs scaffold-examples clean-examples

# Variables
BINARY_NAME=terraform-provider-windows
VERSION?=dev
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
TERRAFORM_PLUGINS_DIR?=~/.terraform.d/plugins
PROVIDER_HOSTNAME=registry.terraform.io
PROVIDER_NAMESPACE=kfrlabs
PROVIDER_TYPE=windows

# Paths
INSTALL_PATH=$(TERRAFORM_PLUGINS_DIR)/$(PROVIDER_HOSTNAME)/$(PROVIDER_NAMESPACE)/$(PROVIDER_TYPE)/$(VERSION)/$(GOOS)_$(GOARCH)

# Colors for output
COLOR_RESET=\033[0m
COLOR_BOLD=\033[1m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_BLUE=\033[34m

##@ General

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make $(COLOR_BLUE)<target>$(COLOR_RESET)\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(COLOR_BLUE)%-20s$(COLOR_RESET) %s\n", $$1, $$2 } /^##@/ { printf "\n$(COLOR_BOLD)%s$(COLOR_RESET)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

build: ## Build the provider binary
	@echo "$(COLOR_GREEN)Building provider...$(COLOR_RESET)"
	go build -o $(BINARY_NAME)
	@echo "$(COLOR_GREEN)✅ Build complete: $(BINARY_NAME)$(COLOR_RESET)"

install: build ## Build and install the provider locally
	@echo "$(COLOR_GREEN)Installing provider to $(INSTALL_PATH)...$(COLOR_RESET)"
	@mkdir -p $(INSTALL_PATH)
	@cp $(BINARY_NAME) $(INSTALL_PATH)/
	@echo "$(COLOR_GREEN)✅ Provider installed$(COLOR_RESET)"

clean: ## Clean build artifacts
	@echo "$(COLOR_YELLOW)Cleaning build artifacts...$(COLOR_RESET)"
	@rm -f $(BINARY_NAME)
	@rm -rf dist/
	@echo "$(COLOR_GREEN)✅ Clean complete$(COLOR_RESET)"

fmt: ## Format Go code
	@echo "$(COLOR_GREEN)Formatting code...$(COLOR_RESET)"
	@go fmt ./...
	@echo "$(COLOR_GREEN)✅ Format complete$(COLOR_RESET)"

lint: ## Run linters
	@echo "$(COLOR_GREEN)Running linters...$(COLOR_RESET)"
	@golangci-lint run ./...
	@echo "$(COLOR_GREEN)✅ Lint complete$(COLOR_RESET)"

vet: ## Run go vet
	@echo "$(COLOR_GREEN)Running go vet...$(COLOR_RESET)"
	@go vet ./...
	@echo "$(COLOR_GREEN)✅ Vet complete$(COLOR_RESET)"

##@ Testing

test: ## Run unit tests
	@echo "$(COLOR_GREEN)Running unit tests...$(COLOR_RESET)"
	@go test -v -cover -timeout=5m ./...

testacc: ## Run acceptance tests
	@echo "$(COLOR_YELLOW)Running acceptance tests...$(COLOR_RESET)"
	TF_ACC=1 go test -v -cover -timeout=30m ./...

test-coverage: ## Run tests with coverage report
	@echo "$(COLOR_GREEN)Running tests with coverage...$(COLOR_RESET)"
	@go test -v -coverprofile=coverage.out -covermode=atomic ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_GREEN)✅ Coverage report: coverage.html$(COLOR_RESET)"

##@ Documentation

docs: ## Generate documentation
	@echo "$(COLOR_GREEN)Generating documentation...$(COLOR_RESET)"
	@tfplugindocs generate --provider-name windows
	@echo "$(COLOR_GREEN)✅ Documentation generated$(COLOR_RESET)"

docs-validate: ## Validate documentation
	@echo "$(COLOR_GREEN)Validating documentation...$(COLOR_RESET)"
	@tfplugindocs validate
	@echo "$(COLOR_GREEN)✅ Documentation validated$(COLOR_RESET)"

##@ Examples Structure

scaffold-examples: ## Create examples directory structure based on code
	@echo "$(COLOR_GREEN)Creating examples structure...$(COLOR_RESET)"
	@mkdir -p examples/provider
	@touch examples/provider/provider.tf
	@echo "$(COLOR_BLUE)  ✅ Created provider examples$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_GREEN)Scanning resources...$(COLOR_RESET)"
	@for file in internal/resources/resource_*.go; do \
		if [ -f "$$file" ]; then \
			resource=$$(basename $$file | sed 's/resource_//g' | sed 's/.go//g'); \
			resource_name="windows_$$resource"; \
			mkdir -p "examples/resources/$$resource_name"; \
			touch "examples/resources/$$resource_name/resource.tf"; \
			touch "examples/resources/$$resource_name/import.sh"; \
			echo "$(COLOR_BLUE)  ✅ Created examples/resources/$$resource_name$(COLOR_RESET)"; \
		fi \
	done
	@echo ""
	@echo "$(COLOR_GREEN)Scanning data sources...$(COLOR_RESET)"
	@for file in internal/datasources/datasource_*.go; do \
		if [ -f "$$file" ]; then \
			datasource=$$(basename $$file | sed 's/datasource_//g' | sed 's/.go//g'); \
			datasource_name="windows_$$datasource"; \
			mkdir -p "examples/data-sources/$$datasource_name"; \
			touch "examples/data-sources/$$datasource_name/data-source.tf"; \
			echo "$(COLOR_BLUE)  ✅ Created examples/data-sources/$$datasource_name$(COLOR_RESET)"; \
		fi \
	done
	@echo ""
	@echo "$(COLOR_GREEN)✅ Examples structure created!$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_YELLOW)Structure:$(COLOR_RESET)"
	@tree -L 3 examples 2>/dev/null || find examples -type f

clean-examples: ## Remove examples directory
	@echo "$(COLOR_YELLOW)Removing examples directory...$(COLOR_RESET)"
	@rm -rf examples/
	@echo "$(COLOR_GREEN)✅ Examples cleaned$(COLOR_RESET)"

list-resources: ## List all resources found in code
	@echo "$(COLOR_GREEN)Resources:$(COLOR_RESET)"
	@for file in internal/resources/resource_*.go; do \
		if [ -f "$$file" ]; then \
			resource=$$(basename $$file | sed 's/resource_//g' | sed 's/.go//g'); \
			echo "  - windows_$$resource"; \
		fi \
	done

list-datasources: ## List all data sources found in code
	@echo "$(COLOR_GREEN)Data Sources:$(COLOR_RESET)"
	@for file in internal/datasources/datasource_*.go; do \
		if [ -f "$$file" ]; then \
			datasource=$$(basename $$file | sed 's/datasource_//g' | sed 's/.go//g'); \
			echo "  - windows_$$datasource"; \
		fi \
	done

##@ Release

release-test: ## Test the release process
	@echo "$(COLOR_GREEN)Testing release process...$(COLOR_RESET)"
	@goreleaser release --snapshot --clean
	@echo "$(COLOR_GREEN)✅ Release test complete$(COLOR_RESET)"

release: ## Create a new release (requires GITHUB_TOKEN)
	@echo "$(COLOR_GREEN)Creating release...$(COLOR_RESET)"
	@goreleaser release --clean
	@echo "$(COLOR_GREEN)✅ Release complete$(COLOR_RESET)"

##@ Dependencies

deps: ## Download dependencies
	@echo "$(COLOR_GREEN)Downloading dependencies...$(COLOR_RESET)"
	@go mod download
	@echo "$(COLOR_GREEN)✅ Dependencies downloaded$(COLOR_RESET)"

deps-update: ## Update dependencies
	@echo "$(COLOR_GREEN)Updating dependencies...$(COLOR_RESET)"
	@go get -u ./...
	@go mod tidy
	@echo "$(COLOR_GREEN)✅ Dependencies updated$(COLOR_RESET)"

deps-vendor: ## Vendor dependencies
	@echo "$(COLOR_GREEN)Vendoring dependencies...$(COLOR_RESET)"
	@go mod vendor
	@echo "$(COLOR_GREEN)✅ Dependencies vendored$(COLOR_RESET)"

##@ Tools

tools: ## Install development tools
	@echo "$(COLOR_GREEN)Installing development tools...$(COLOR_RESET)"
	@go install github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/goreleaser/goreleaser@latest
	@echo "$(COLOR_GREEN)✅ Tools installed$(COLOR_RESET)"

##@ Complete Workflow

all: fmt vet lint test build ## Run all checks and build

dev: clean build install ## Quick development cycle: clean, build, and install

doc-complete: scaffold-examples docs docs-validate ## Complete documentation workflow
	@echo ""
	@echo "$(COLOR_GREEN)========================================$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)Documentation workflow complete!$(COLOR_RESET)"
	@echo "$(COLOR_GREEN)========================================$(COLOR_RESET)"
	@echo ""
	@echo "$(COLOR_YELLOW)Next steps:$(COLOR_RESET)"
	@echo "  1. Fill in the examples in examples/"
	@echo "  2. Run 'make docs' to regenerate documentation"
	@echo "  3. Review docs/ directory"
	@echo ""

ci: fmt vet lint test ## Run CI checks
	@echo "$(COLOR_GREEN)✅ All CI checks passed$(COLOR_RESET)"

.DEFAULT_GOAL := help