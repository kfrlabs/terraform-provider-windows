// Package winclient — LegacyPackageClient interface and DTOs.
//
// Defines the contract for managing legacy Windows installers (.msi via
// msiexec, .exe via Start-Process) over WinRM. The concrete implementation
// will be authored by the ProviderCoder task in a sibling file.
//
// Spec alignment: windows_legacy_package spec v1 (2026-05-05).
package winclient

import "context"

// ---------------------------------------------------------------------------
// LegacyPackageInput — desired configuration consumed by Create / Update
// ---------------------------------------------------------------------------

// LegacyPackageInput carries the user-provided configuration for a legacy
// package operation. Empty / zero values mean "unset" (use spec defaults).
//
// JSON tags match the lower_snake keys used by the PowerShell payloads
// emitted via ConvertTo-Json on the target host.
type LegacyPackageInput struct {
	// Name is the logical Terraform identifier and display label.
	Name string `json:"name"`

	// InstallerType selects the engine: "msi" (msiexec) or "exe" (Start-Process).
	InstallerType string `json:"installer_type"`

	// SourcePath is the local Windows path to the installer. Mutually
	// exclusive with SourceURL.
	SourcePath string `json:"source_path,omitempty"`

	// SourceURL is the http(s) URL the installer is downloaded from on the
	// target host. Mutually exclusive with SourcePath.
	SourceURL string `json:"source_url,omitempty"`

	// Checksum is the expected installer hash, format "<algo>:<hex>".
	Checksum string `json:"checksum,omitempty"`

	// InsecureSkipVerify disables TLS certificate validation for SourceURL.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`

	// ProductID is the MSI ProductCode GUID. Auto-extracted from the MSI
	// when empty (MSI only).
	ProductID string `json:"product_id,omitempty"`

	// DisplayNamePattern locates EXE installs in the Uninstall registry
	// hives by DisplayName. Required for EXE when UninstallCommand is empty.
	DisplayNamePattern string `json:"display_name_pattern,omitempty"`

	// InstallArgs are extra arguments passed to the installer.
	InstallArgs []string `json:"install_args,omitempty"`

	// UninstallArgs are extra arguments passed at uninstall time.
	UninstallArgs []string `json:"uninstall_args,omitempty"`

	// UninstallCommand overrides the registry UninstallString for EXE.
	UninstallCommand string `json:"uninstall_command,omitempty"`

	// ValidExitCodes are the exit codes treated as success. Default [0, 3010].
	ValidExitCodes []int64 `json:"valid_exit_codes,omitempty"`

	// WorkingDirectory is the CWD for the installer process.
	WorkingDirectory string `json:"working_directory,omitempty"`

	// TimeoutSeconds bounds the install/uninstall execution. Default 1800.
	TimeoutSeconds int64 `json:"timeout_seconds,omitempty"`

	// LogPath is the path to the MSI /l*v log or EXE stdout/stderr capture.
	LogPath string `json:"log_path,omitempty"`

	// Environment holds extra env vars injected into the installer process.
	// Sensitive: may carry license keys or proxy credentials.
	Environment map[string]string `json:"environment,omitempty"`
}

// ---------------------------------------------------------------------------
// LegacyPackageState — observed state returned by Read / Create / Update
// ---------------------------------------------------------------------------

// LegacyPackageState is the snapshot of the package as observed on the
// target host. JSON tags mirror the PowerShell ConvertTo-Json output
// produced by the read pipeline against the Uninstall registry hives.
type LegacyPackageState struct {
	// ID is the Terraform identifier: ProductCode GUID for MSI, exact
	// resolved DisplayName for EXE.
	ID string `json:"id"`

	// ProductID is the MSI ProductCode GUID (empty for EXE).
	ProductID string `json:"product_id,omitempty"`

	// LogPath is the resolved log path (auto-generated when not user-set).
	LogPath string `json:"log_path,omitempty"`

	// InstalledVersion is the DisplayVersion read from the registry.
	InstalledVersion string `json:"installed_version,omitempty"`

	// Installed reports whether the package is currently detected.
	Installed bool `json:"installed"`

	// InstallDate is the registry InstallDate, normalized to ISO-8601 when
	// parseable.
	InstallDate string `json:"install_date,omitempty"`
}

// ---------------------------------------------------------------------------
// LegacyPackageClient — CRUD contract
// ---------------------------------------------------------------------------

// LegacyPackageClient is the contract used by the resource layer to manage
// legacy Windows installers via PowerShell over WinRM.
//
// Implementations MUST:
//
//   - Treat MSI exit code 3010 as success (reboot pending) by default.
//   - Search both the 64-bit and Wow6432Node Uninstall hives at Read time.
//   - Return (nil, nil) from Read when the package is no longer detected so
//     the resource layer can flag drift and schedule re-create.
//   - Validate Checksum BEFORE executing the installer.
//   - Kill the entire process tree on TimeoutSeconds expiry, not just the
//     parent process.
type LegacyPackageClient interface {
	// Create runs the installer end-to-end: source resolution, checksum
	// verification, exec, and state read-back.
	Create(ctx context.Context, in LegacyPackageInput) (*LegacyPackageState, error)

	// Read refreshes the observed state from the Uninstall registry hives.
	// Returns (nil, nil) when the package is no longer present.
	Read(ctx context.Context, id string) (*LegacyPackageState, error)

	// Update applies in-place mutations (valid_exit_codes, timeout_seconds,
	// log_path, environment). All other changes are ForceNew at the
	// resource layer and never reach this method.
	Update(ctx context.Context, id string, in LegacyPackageInput) (*LegacyPackageState, error)

	// Delete uninstalls the package. MSI uses msiexec /x; EXE prefers
	// UninstallCommand and falls back to the parsed registry UninstallString.
	Delete(ctx context.Context, id string) error
}
