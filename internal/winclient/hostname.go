// Package winclient: Windows hostname (NetBIOS computer name) CRUD over WinRM.
//
// HostnameClient is the concrete WindowsHostnameClient backing the
// windows_hostname Terraform resource. All operations execute PowerShell
// scripts wrapped in a JSON envelope (Emit-OK/Emit-Err) so stdout is
// machine-parseable regardless of the Windows locale.
//
// Spec alignment: windows_hostname spec v1 (2026-04-25).
//
// Security invariants:
//   - The desired name is interpolated via psQuote (single-quoted PS literal)
//     so $var / backtick / subexpression injection is impossible (EC-1).
//   - All scripts are sent via -EncodedCommand by Client.RunPowerShell.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Compile-time assertion: HostnameClient satisfies WindowsHostnameClient.
var _ WindowsHostnameClient = (*HostnameClient)(nil)

// HostnameClient is the PowerShell/WinRM-backed WindowsHostnameClient.
type HostnameClient struct {
	c *Client
}

// NewHostnameClient wraps the given WinRM Client.
func NewHostnameClient(c *Client) *HostnameClient { return &HostnameClient{c: c} }

// runHostnamePowerShell is the package-level indirection used by
// HostnameClient. Tests may override it; production code must not.
var runHostnamePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// netbiosRe / pureNumericRe re-validate the desired name on the client side
// (defence-in-depth — EC-1).
var (
	netbiosRe     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$`)
	pureNumericRe = regexp.MustCompile(`^[0-9]+$`)
)

// validateNetBIOS returns nil if name complies with the NetBIOS rule used by
// the windows_hostname schema. Otherwise it returns an *HostnameError of
// kind invalid_name.
func validateNetBIOS(name string) error {
	if name == "" {
		return NewHostnameError(HostnameErrorInvalidName,
			"hostname is empty", nil,
			map[string]string{"name": name})
	}
	if len(name) > 15 {
		return NewHostnameError(HostnameErrorInvalidName,
			fmt.Sprintf("hostname %q exceeds the 15-character NetBIOS limit", name), nil,
			map[string]string{"name": name, "length": fmt.Sprintf("%d", len(name))})
	}
	if !netbiosRe.MatchString(name) {
		return NewHostnameError(HostnameErrorInvalidName,
			fmt.Sprintf("hostname %q does not match the NetBIOS rule (1..15 chars, alphanumeric + hyphen, cannot start/end with hyphen)", name), nil,
			map[string]string{"name": name})
	}
	if pureNumericRe.MatchString(name) {
		return NewHostnameError(HostnameErrorInvalidName,
			fmt.Sprintf("hostname %q is purely numeric, which is not a valid NetBIOS computer name", name), nil,
			map[string]string{"name": name})
	}
	return nil
}

// hostnamePSResponse is the JSON envelope produced by Emit-OK/Emit-Err.
type hostnamePSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// hostnameStatePayload is the data shape emitted by the Read script.
type hostnameStatePayload struct {
	MachineID     string `json:"machine_id"`
	CurrentName   string `json:"current_name"`
	PendingName   string `json:"pending_name"`
	RebootPending bool   `json:"reboot_pending"`
	PartOfDomain  bool   `json:"part_of_domain"`
	Domain        string `json:"domain"`
}

// psHostnameHeader prepends Emit-OK/Emit-Err and Classify-Hostname.
//
// Classify-Hostname maps Rename-Computer / WinRM error substrings to
// HostnameErrorKind values. Detection is best-effort and substring-based
// because Windows error messages are localised.
const psHostnameHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}
function Classify-Hostname([string]$Msg) {
  if ($Msg -match 'Access is denied' -or $Msg -match 'AccessDenied' -or $Msg -match 'RenameComputerNotAuthorized' -or $Msg -match 'not authorized') { return 'permission_denied' }
  if ($Msg -match 'computer name' -and ($Msg -match 'invalid' -or $Msg -match 'not valid')) { return 'invalid_name' }
  return 'unknown'
}

function Read-HostnameState {
  $cs   = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
  $act  = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name ComputerName -ErrorAction Stop).ComputerName
  $pend = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'       -Name ComputerName -ErrorAction Stop).ComputerName
  $guid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography'                                  -Name MachineGuid  -ErrorAction Stop).MachineGuid
  $rp   = ($act.ToLowerInvariant() -ne $pend.ToLowerInvariant())
  return [ordered]@{
    machine_id     = [string]$guid
    current_name   = [string]$act
    pending_name   = [string]$pend
    reboot_pending = [bool]$rp
    part_of_domain = [bool]$cs.PartOfDomain
    domain         = [string]$cs.Domain
  }
}
`

// runHostnameEnvelope executes script (prepended with psHostnameHeader) and
// parses the JSON envelope. Transport / cancellation errors that bypass
// Emit-Err are mapped to HostnameErrorUnreachable / HostnameErrorUnknown.
func (h *HostnameClient) runHostnameEnvelope(ctx context.Context, op, script string, baseCtx map[string]string) (*hostnamePSResponse, error) {
	full := psHostnameHeader + "\n" + script
	stdout, stderr, err := runHostnamePowerShell(ctx, h.c, full)

	if baseCtx == nil {
		baseCtx = map[string]string{}
	}
	baseCtx["operation"] = op
	baseCtx["host"] = h.c.cfg.Host
	baseCtx["port"] = fmt.Sprintf("%d", h.c.cfg.Port)
	if h.c.cfg.UseHTTPS {
		baseCtx["transport"] = "https"
	} else {
		baseCtx["transport"] = "http"
	}

	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, NewHostnameError(HostnameErrorUnreachable,
				fmt.Sprintf("operation %q timed out or was cancelled", op),
				ctxErr, baseCtx)
		}
		baseCtx["stderr"] = truncate(stderr, 2048)
		baseCtx["stdout"] = truncate(stdout, 2048)
		return nil, NewHostnameError(HostnameErrorUnreachable,
			fmt.Sprintf("WinRM transport error during %q", op),
			err, baseCtx)
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		baseCtx["stdout"] = truncate(stdout, 2048)
		baseCtx["stderr"] = truncate(stderr, 2048)
		return nil, NewHostnameError(HostnameErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op), nil, baseCtx)
	}
	var resp hostnamePSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		baseCtx["stdout"] = truncate(stdout, 2048)
		return nil, NewHostnameError(HostnameErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op), jerr, baseCtx)
	}
	if !resp.OK {
		kind := mapHostnameKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		for k, v := range baseCtx {
			if _, ok := ctxMap[k]; !ok {
				ctxMap[k] = v
			}
		}
		return &resp, NewHostnameError(kind, resp.Message, nil, ctxMap)
	}
	return &resp, nil
}

// mapHostnameKind translates a PS-side "kind" string to a typed
// HostnameErrorKind. Unknown values fall through to HostnameErrorUnknown.
func mapHostnameKind(k string) HostnameErrorKind {
	switch k {
	case string(HostnameErrorInvalidName),
		string(HostnameErrorPermission),
		string(HostnameErrorDomainJoined),
		string(HostnameErrorUnreachable),
		string(HostnameErrorMachineMismatch),
		string(HostnameErrorConcurrent):
		return HostnameErrorKind(k)
	default:
		return HostnameErrorUnknown
	}
}

// payloadToState projects a hostnameStatePayload onto the public HostnameState.
func payloadToState(p hostnameStatePayload) *HostnameState {
	return &HostnameState{
		MachineID:     p.MachineID,
		CurrentName:   p.CurrentName,
		PendingName:   p.PendingName,
		RebootPending: p.RebootPending,
		PartOfDomain:  p.PartOfDomain,
		Domain:        p.Domain,
	}
}

// readState runs Read-HostnameState and parses the response.
func (h *HostnameClient) readState(ctx context.Context, op string) (*HostnameState, error) {
	script := "try { $s = Read-HostnameState; Emit-OK $s } catch { Emit-Err (Classify-Hostname $_.Exception.Message) $_.Exception.Message @{} }"
	resp, err := h.runHostnameEnvelope(ctx, op, script, nil)
	if err != nil {
		return nil, err
	}
	var p hostnameStatePayload
	if jerr := json.Unmarshal(resp.Data, &p); jerr != nil {
		return nil, NewHostnameError(HostnameErrorUnknown,
			fmt.Sprintf("failed to parse hostname state from %q", op), jerr,
			map[string]string{"host": h.c.cfg.Host})
	}
	return payloadToState(p), nil
}

// guardDomain returns ErrHostnameDomainJoined when state.PartOfDomain is true.
func guardDomain(state *HostnameState, host string) error {
	if state.PartOfDomain {
		return NewHostnameError(HostnameErrorDomainJoined,
			fmt.Sprintf("windows_hostname v1 does not support domain-joined machines (host=%s, domain=%s); a domain-joined rename requires -DomainCredential", host, state.Domain),
			nil, map[string]string{"host": host, "domain": state.Domain})
	}
	return nil
}

// renameAndRead performs Rename-Computer with the supplied input and re-reads
// the state. Idempotent when CurrentName == PendingName == input.Name.
func (h *HostnameClient) renameAndRead(ctx context.Context, input HostnameInput, expectedID string) (*HostnameState, error) {
	if err := validateNetBIOS(input.Name); err != nil {
		return nil, err
	}

	cur, err := h.readState(ctx, "pre-rename-read")
	if err != nil {
		return nil, err
	}
	if err := guardDomain(cur, h.c.cfg.Host); err != nil {
		return nil, err
	}
	if expectedID != "" && !strings.EqualFold(cur.MachineID, expectedID) {
		return nil, NewHostnameError(HostnameErrorMachineMismatch,
			fmt.Sprintf("live MachineGuid %q does not match expected %q; the underlying machine has been replaced", cur.MachineID, expectedID),
			nil, map[string]string{"expected_id": expectedID, "observed_id": cur.MachineID, "host": h.c.cfg.Host})
	}

	desired := input.Name
	if strings.EqualFold(cur.CurrentName, desired) && strings.EqualFold(cur.PendingName, desired) {
		return cur, nil // EC-2: already at target name
	}

	forceFlag := ""
	if input.Force {
		forceFlag = " -Force"
	}
	script := fmt.Sprintf(`
try {
  $null = Rename-Computer -NewName %s%s -PassThru -ErrorAction Stop
  $s = Read-HostnameState
  Emit-OK $s
} catch {
  $msg = $_.Exception.Message
  Emit-Err (Classify-Hostname $msg) $msg @{ desired = %s; observed_pending = (try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name ComputerName -ErrorAction Stop).ComputerName } catch { '' }) }
}
`, psQuote(desired), forceFlag, psQuote(desired))

	resp, err := h.runHostnameEnvelope(ctx, "rename", script,
		map[string]string{"desired_name": desired, "current_name": cur.CurrentName, "pending_name": cur.PendingName})
	if err != nil {
		return nil, err
	}
	var p hostnameStatePayload
	if jerr := json.Unmarshal(resp.Data, &p); jerr != nil {
		return nil, NewHostnameError(HostnameErrorUnknown,
			"failed to parse hostname state after Rename-Computer", jerr,
			map[string]string{"host": h.c.cfg.Host})
	}
	post := payloadToState(p)

	// EC-11: if pending_name does not reflect the desired name, an external
	// rename happened concurrently.
	if !strings.EqualFold(post.PendingName, desired) {
		return post, NewHostnameError(HostnameErrorConcurrent,
			fmt.Sprintf("observed pending_name %q does not match desired %q after Rename-Computer; an external rename may have occurred", post.PendingName, desired),
			nil, map[string]string{
				"desired_name":     desired,
				"observed_pending": post.PendingName,
				"observed_current": post.CurrentName,
				"host":             h.c.cfg.Host,
			})
	}
	return post, nil
}

// Create renames the host to input.Name (idempotent).
func (h *HostnameClient) Create(ctx context.Context, input HostnameInput) (*HostnameState, error) {
	return h.renameAndRead(ctx, input, "")
}

// Read aggregates Win32_ComputerSystem + the three HKLM registry reads. If the
// live MachineGuid differs from the supplied id, returns ErrHostnameMachineMismatch
// (EC-10).
func (h *HostnameClient) Read(ctx context.Context, id string) (*HostnameState, error) {
	state, err := h.readState(ctx, "read")
	if err != nil {
		return nil, err
	}
	if id != "" && !strings.EqualFold(state.MachineID, id) {
		return state, NewHostnameError(HostnameErrorMachineMismatch,
			fmt.Sprintf("live MachineGuid %q does not match state id %q; the underlying machine has been replaced", state.MachineID, id),
			nil, map[string]string{"expected_id": id, "observed_id": state.MachineID, "host": h.c.cfg.Host})
	}
	return state, nil
}

// Update renames the host in place; same semantics as Create plus a
// MachineGuid guard (EC-10) and concurrent-rename detection (EC-11).
func (h *HostnameClient) Update(ctx context.Context, id string, input HostnameInput) (*HostnameState, error) {
	return h.renameAndRead(ctx, input, id)
}

// Delete is a documented no-op (EC-7). Returns nil unconditionally.
func (h *HostnameClient) Delete(_ context.Context, _ string) error {
	return nil
}
