// LegacyPackageClient PowerShell/WinRM-backed implementation.
//
// Implements LegacyPackageClient by executing PowerShell scripts over WinRM.
// The full input payload is forwarded to the script via stdin as JSON
// (Client.RunPowerShellWithInput) so that complex fields (lists, maps) are
// transferred without any PowerShell quoting concern. Every script emits a
// single JSON envelope through Emit-OK / Emit-Err so stdout is locale
// independent and machine-parseable.
//
// Spec alignment: windows_legacy_package spec v1 (2026-05-05).
package winclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Compile-time assertion: LegacyPackageClientImpl satisfies LegacyPackageClient.
var _ LegacyPackageClient = (*LegacyPackageClientImpl)(nil)

// LegacyPackageError is the structured error type returned by every
// LegacyPackageClient method on a non-transport failure (Emit-Err on the
// PowerShell side or a Go-side parse error). It mirrors the shape of
// ServiceError / WingetPackageError used by the rest of the package.
type LegacyPackageError struct {
	// Kind is the machine-readable error category (matches the PS-side `kind`).
	Kind string
	// Message is the human-readable description.
	Message string
	// Context carries structured key/value diagnostic data.
	Context map[string]string
	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *LegacyPackageError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("windows_legacy_package [%s]: %s: %v", e.Kind, e.Message, e.Cause)
	}
	return fmt.Sprintf("windows_legacy_package [%s]: %s", e.Kind, e.Message)
}

// Unwrap returns the underlying cause.
func (e *LegacyPackageError) Unwrap() error { return e.Cause }

// IsLegacyPackageError reports whether err is a *LegacyPackageError with the
// given kind.
func IsLegacyPackageError(err error, kind string) bool {
	var e *LegacyPackageError
	if errors.As(err, &e) {
		return e.Kind == kind
	}
	return false
}

// LegacyPackageClientImpl is the concrete LegacyPackageClient.
type LegacyPackageClientImpl struct {
	c *Client
}

// NewLegacyPackageClient constructs a LegacyPackageClientImpl wrapping the
// given WinRM Client.
func NewLegacyPackageClient(c *Client) *LegacyPackageClientImpl {
	return &LegacyPackageClientImpl{c: c}
}

// readPayload is the stdin JSON payload consumed by the read script.
type readPayload struct {
	ID string `json:"id"`
}

// deletePayload is the stdin JSON payload consumed by the delete script.
type deletePayload struct {
	ID               string   `json:"id"`
	UninstallCommand string   `json:"uninstall_command,omitempty"`
	UninstallArgs    []string `json:"uninstall_args,omitempty"`
	ValidExitCodes   []int64  `json:"valid_exit_codes,omitempty"`
	TimeoutSeconds   int64    `json:"timeout_seconds,omitempty"`
}

// runEnvelope executes script over WinRM with stdin piped from payload (JSON
// encoded) and decodes the JSON envelope written to stdout by Emit-OK /
// Emit-Err. Transport errors are wrapped as LegacyPackageError{Kind:"unknown"}.
func (l *LegacyPackageClientImpl) runEnvelope(ctx context.Context, op string, payload any, script string) (*psResponse, error) {
	stdin, err := json.Marshal(payload)
	if err != nil {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: "marshal payload", Cause: err,
			Context: map[string]string{"operation": op},
		}
	}
	full := lpHeader + "\n" + script
	// Route through the package-level runPSInput seam (also used by local_user.go)
	// so unit tests can stub the WinRM transport without a real host.
	stdout, stderr, err := runPSInput(ctx, l.c, full, string(stdin))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &LegacyPackageError{
				Kind: "timeout", Message: fmt.Sprintf("operation %q cancelled or timed out", op),
				Cause: ctxErr,
				Context: map[string]string{
					"operation": op,
					"host":      l.c.cfg.Host,
				},
			}
		}
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: fmt.Sprintf("WinRM transport error during %q", op),
			Cause: err,
			Context: map[string]string{
				"operation": op,
				"host":      l.c.cfg.Host,
				"stderr":    truncate(stderr, 2048),
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: fmt.Sprintf("no JSON envelope returned from %q", op),
			Context: map[string]string{
				"operation": op,
				"host":      l.c.cfg.Host,
				"stderr":    truncate(stderr, 2048),
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: fmt.Sprintf("invalid JSON envelope from %q", op),
			Cause: jerr,
			Context: map[string]string{
				"operation": op,
				"host":      l.c.cfg.Host,
				"stdout":    truncate(stdout, 2048),
			},
		}
	}

	if !resp.OK {
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["host"] = l.c.cfg.Host
		return &resp, &LegacyPackageError{
			Kind: resp.Kind, Message: resp.Message, Context: ctxMap,
		}
	}
	return &resp, nil
}

// parseLPState decodes the Data field of resp into a *LegacyPackageState.
// Returns (nil, nil) when resp.Data is JSON null (package absent).
func parseLPState(resp *psResponse) (*LegacyPackageState, error) {
	if resp.Data == nil || string(resp.Data) == "null" {
		return nil, nil
	}
	var st LegacyPackageState
	if err := json.Unmarshal(resp.Data, &st); err != nil {
		return nil, &LegacyPackageError{
			Kind: "unknown", Message: "failed to parse legacy package state JSON", Cause: err,
		}
	}
	return &st, nil
}

// ---------------------------------------------------------------------------
// LegacyPackageClient interface implementation
// ---------------------------------------------------------------------------

// Create runs the installer end-to-end: source resolution, checksum
// verification, exec, exit-code validation, and state read-back.
func (l *LegacyPackageClientImpl) Create(ctx context.Context, in LegacyPackageInput) (*LegacyPackageState, error) {
	resp, err := l.runEnvelope(ctx, "Create", in, lpCreateBody)
	if err != nil {
		return nil, err
	}
	return parseLPState(resp)
}

// Read refreshes the observed state from the Uninstall registry hives.
// Returns (nil, nil) when the package is no longer present so the resource
// layer can flag drift and schedule re-create.
func (l *LegacyPackageClientImpl) Read(ctx context.Context, id string) (*LegacyPackageState, error) {
	resp, err := l.runEnvelope(ctx, "Read", readPayload{ID: id}, lpReadBody)
	if err != nil {
		return nil, err
	}
	return parseLPState(resp)
}

// Update is a no-op on the Windows host: only state-level fields
// (valid_exit_codes, timeout_seconds, log_path, environment) are updatable
// in place and they affect future invocations only. The current observed
// state is refreshed via Read.
func (l *LegacyPackageClientImpl) Update(ctx context.Context, id string, _ LegacyPackageInput) (*LegacyPackageState, error) {
	return l.Read(ctx, id)
}

// Delete uninstalls the package. MSI uses msiexec /x; EXE prefers
// UninstallCommand and falls back to the parsed registry UninstallString
// (QuietUninstallString preferred).
func (l *LegacyPackageClientImpl) Delete(ctx context.Context, id string) error {
	_, err := l.runEnvelope(ctx, "Delete", deletePayload{ID: id}, lpDeleteBody)
	return err
}
