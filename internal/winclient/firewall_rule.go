// Package winclient - FirewallRuleClient is the concrete
// WindowsFirewallRuleClient backed by PowerShell over WinRM.
//
// Security invariants:
//   - All user-supplied strings are interpolated via psQuote (single-quoted
//     PowerShell literal with embedded single-quotes doubled); no raw
//     concatenation of user input into PS scripts.
//   - All list values use psQuoteList rendering; no raw injection.
//   - No credentials are written to FirewallRuleError.Message or Context.
//
// Reused helpers from service.go (same package):
//   - psQuote, psQuoteList        - safe PS string/array literals
//   - extractLastJSONLine          - scan stdout for JSON envelope
//   - truncate                     - cap strings for diagnostic context
//   - runPowerShell                - package-level hook (testable)
//   - psResponse                   - Emit-OK / Emit-Err JSON envelope struct
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: FirewallRuleClient satisfies WindowsFirewallRuleClient.
var _ WindowsFirewallRuleClient = (*FirewallRuleClient)(nil)

// FirewallRuleClient is the PowerShell/WinRM-backed WindowsFirewallRuleClient.
type FirewallRuleClient struct {
	c *Client
}

// NewFirewallRuleClient constructs a FirewallRuleClient wrapping the given
// WinRM Client.
func NewFirewallRuleClient(c *Client) *FirewallRuleClient {
	return &FirewallRuleClient{c: c}
}

// ---------------------------------------------------------------------------
// PowerShell header
// ---------------------------------------------------------------------------

// frPsHeader is prepended to every firewall-rule PS script.
// It pins the session culture to InvariantCulture (ADR-FR-5) so enum
// .ToString() values are always English regardless of the host locale, and
// defines the shared helper functions used by all operations.
//
// Note: Go raw-string literals (backtick-delimited) must not contain PS
// backtick sequences (`n, `t). None are needed here — [char]10 is used for
// newlines inside PS strings where required, and single-quoted PS literals
// avoid all expansion.
const frPsHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
[System.Threading.Thread]::CurrentThread.CurrentCulture   = [System.Globalization.CultureInfo]::InvariantCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = [System.Globalization.CultureInfo]::InvariantCulture

function Emit-OK([object]$Data) {
  $obj  = [ordered]@{ ok = $true; data = $Data }
  $json = ($obj | ConvertTo-Json -Depth 10 -Compress)
  [Console]::Out.WriteLine($json)
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj  = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Classify-FR([string]$Msg) {
  if ($Msg -match 'No MSFT_NetFirewallRule' -or
      $Msg -match 'ObjectNotFound' -or
      $Msg -match 'ItemNotFoundException' -or
      $Msg -match 'not exist')
  { return 'not_found' }
  if ($Msg -match 'already exists' -or $Msg -match 'AlreadyExists')
  { return 'already_exists' }
  if ($Msg -match 'Access is denied' -or
      $Msg -match 'PermissionDenied' -or
      $Msg -match 'Unauthorized')
  { return 'permission_denied' }
  if ($Msg -match '[Ii]nvalid' -or $Msg -match '[Aa]rgument')
  { return 'invalid_input' }
  return 'unknown'
}

function Norm-Arr([object]$val) {
  if ($null -eq $val) { return @('Any') }
  $joined = [string]::Join(',', @($val | ForEach-Object { [string]$_ }))
  if ($joined -eq '' -or $joined -eq 'Any') { return @('Any') }
  $parts = @($joined -split ',\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
  if ($parts.Count -eq 0) { return @('Any') }
  return $parts
}
`

// ---------------------------------------------------------------------------
// Read state body
// ---------------------------------------------------------------------------

// frReadBody is the PS script fragment (without header) that reads a firewall
// rule and emits a normalised state JSON. Uses @@NAME@@ and @@PSTORE@@
// placeholders replaced by buildFirewallReplacer.
const frReadBody = `
$ruleName    = @@NAME@@
$policyStore = @@PSTORE@@

try {
  $rule = Get-NetFirewallRule -Name $ruleName -PolicyStore $policyStore -ErrorAction Stop
} catch {
  $k = Classify-FR $_.Exception.Message
  if ($k -eq 'not_found') { Emit-OK $null } else { Emit-Err $k ([string]$_.Exception.Message) @{} }
  return
}

$pf  = $rule | Get-NetFirewallPortFilter
$af  = $rule | Get-NetFirewallAddressFilter
$apf = $rule | Get-NetFirewallApplicationFilter
$sf  = $rule | Get-NetFirewallServiceFilter
$itf = $rule | Get-NetFirewallInterfaceTypeFilter

# Profile: split comma-separated enum string to array (ADR-FR-6)
$profileStr = [string]$rule.Profile
if ($profileStr -eq '' -or $null -eq $profileStr) { $profileStr = 'Any' }
$profileArr = @($profileStr -split ',\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
if ($profileArr.Count -eq 0) { $profileArr = @('Any') }

# Direction: int-based map for locale safety (ADR-FR-5)
$dirMap = @{ 1 = 'Inbound'; 2 = 'Outbound' }
$dirInt = [int]$rule.Direction
$dir    = if ($dirMap.ContainsKey($dirInt)) { $dirMap[$dirInt] } else { [string]$rule.Direction }

# Action: int-based map
$actMap = @{ 2 = 'Allow'; 4 = 'Block'; 0 = 'NotConfigured' }
$actInt = [int]$rule.Action
$act    = if ($actMap.ContainsKey($actInt)) { $actMap[$actInt] } else { [string]$rule.Action }

# EdgeTraversalPolicy: int-based map
$etpMap = @{ 0 = 'Block'; 1 = 'Allow'; 2 = 'DeferToUser'; 3 = 'DeferToApp' }
$etpInt = [int]$rule.EdgeTraversalPolicy
$etp    = if ($etpMap.ContainsKey($etpInt)) { $etpMap[$etpInt] } else { [string]$rule.EdgeTraversalPolicy }

# InterfaceType: int-based map (flags: Any=0, Wired=1, Wireless=2, RemoteAccess=4)
$itMap = @{ 0 = 'Any'; 1 = 'Wired'; 2 = 'Wireless'; 4 = 'RemoteAccess' }
$itInt = [int]$itf.InterfaceType
$it    = if ($itMap.ContainsKey($itInt)) { $itMap[$itInt] } else { [string]$itf.InterfaceType }

# Protocol: coerce to string; numeric protocols (GRE=47 etc.) are preserved
$proto = [string]$pf.Protocol
if ($proto -eq '' -or $null -eq $proto) { $proto = 'Any' }

# Program / Service: normalise wildcards/empty to 'Any'
$prog = [string]$apf.Program
if ($prog -eq '' -or $prog -eq '*') { $prog = 'Any' }

$svc = [string]$sf.Service
if ($svc -eq '' -or $svc -eq '*') { $svc = 'Any' }

# Enabled: compare as string to handle both bool and string forms
$enabled = ($rule.Enabled -eq $true -or [string]$rule.Enabled -eq 'True')

$state = [ordered]@{
  name                  = [string]$rule.Name
  display_name          = [string]$rule.DisplayName
  description           = [string]$rule.Description
  enabled               = [bool]$enabled
  direction             = $dir
  action                = $act
  profile               = [array]$profileArr
  edge_traversal_policy = $etp
  group                 = [string]$rule.Group
  policy_store          = $policyStore
  protocol              = $proto
  local_port            = [array](Norm-Arr $pf.LocalPort)
  remote_port           = [array](Norm-Arr $pf.RemotePort)
  local_address         = [array](Norm-Arr $af.LocalAddress)
  remote_address        = [array](Norm-Arr $af.RemoteAddress)
  program               = $prog
  service               = $svc
  interface_type        = $it
}
Emit-OK $state
`

// frCreateBody is the PS script fragment for Create.
// Uses @@NAME@@, @@PSTORE@@, @@PARAMS@@ placeholders.
const frCreateBody = `
$ruleName    = @@NAME@@
$policyStore = @@PSTORE@@

# Pre-existence check (FirewallRuleClient spec: Create returns already_exists)
try {
  $null = Get-NetFirewallRule -Name $ruleName -PolicyStore $policyStore -ErrorAction Stop
  Emit-Err 'already_exists' "Firewall rule '$ruleName' already exists in policy store '$policyStore'" @{}
  return
} catch {
  $k = Classify-FR $_.Exception.Message
  if ($k -ne 'not_found') {
    Emit-Err $k ([string]$_.Exception.Message) @{}
    return
  }
  # 'not_found' -> rule does not exist, proceed with creation
}

@@PARAMS@@

try {
  New-NetFirewallRule @params | Out-Null
  Emit-OK $null
} catch {
  Emit-Err (Classify-FR $_.Exception.Message) ([string]$_.Exception.Message) @{}
}
`

// frUpdateBody is the PS script fragment for Update.
// Uses @@NAME@@, @@PSTORE@@, @@PARAMS@@ placeholders.
const frUpdateBody = `
$ruleName    = @@NAME@@
$policyStore = @@PSTORE@@

@@PARAMS@@

try {
  Set-NetFirewallRule @params
  Emit-OK $null
} catch {
  Emit-Err (Classify-FR $_.Exception.Message) ([string]$_.Exception.Message) @{}
}
`

// frDeleteBody is the PS script fragment for Delete.
// Uses @@NAME@@, @@PSTORE@@ placeholders.
const frDeleteBody = `
$ruleName    = @@NAME@@
$policyStore = @@PSTORE@@

try {
  Remove-NetFirewallRule -Name $ruleName -PolicyStore $policyStore -ErrorAction Stop
  Emit-OK $null
} catch {
  $k = Classify-FR $_.Exception.Message
  if ($k -eq 'not_found') {
    Emit-OK $null  # idempotent: already gone
    return
  }
  Emit-Err $k ([string]$_.Exception.Message) @{}
}
`

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mapFirewallKind maps a PS-emitted kind string to FirewallRuleErrorKind.
func mapFirewallKind(k string) FirewallRuleErrorKind {
	switch FirewallRuleErrorKind(k) {
	case FirewallRuleErrorNotFound,
		FirewallRuleErrorAlreadyExists,
		FirewallRuleErrorPermission,
		FirewallRuleErrorReadOnlyStore,
		FirewallRuleErrorInvalidInput:
		return FirewallRuleErrorKind(k)
	default:
		return FirewallRuleErrorUnknown
	}
}

// checkWritableStore returns ErrFirewallRuleReadOnlyStore for GroupPolicy/RSOP
// stores that this provider cannot write to (ADR-FR-3).
func checkWritableStore(policyStore string) error {
	switch policyStore {
	case "GroupPolicy", "RSOP":
		return NewFirewallRuleError(
			FirewallRuleErrorReadOnlyStore,
			fmt.Sprintf(
				"policy store %q is read-only; Create/Update/Delete operations are not "+
					"supported. Use GPO management tools for GroupPolicy/RSOP stores.",
				policyStore,
			),
			nil,
			map[string]string{"policy_store": policyStore},
		)
	}
	return nil
}

// buildFirewallReplacer returns a strings.Replacer for the two standard
// placeholders shared by all firewall PS scripts.
func buildFirewallReplacer(name, policyStore string) *strings.Replacer {
	return strings.NewReplacer(
		"@@NAME@@", psQuote(name),
		"@@PSTORE@@", psQuote(policyStore),
	)
}

// buildFirewallParams constructs the PowerShell $params hashtable assignment
// string that is injected at @@PARAMS@@ in Create and Update scripts.
// op must be "create" or "update"; "group" is only written for "create"
// because it is ForceNew and Set-NetFirewallRule does not accept it.
func buildFirewallParams(op, name, policyStore string, input FirewallRuleInput) string {
	var sb strings.Builder
	sb.WriteString("$params = @{\n")

	// Identity (always present)
	sb.WriteString(fmt.Sprintf("  Name        = %s\n", psQuote(name)))
	sb.WriteString(fmt.Sprintf("  PolicyStore = %s\n", psQuote(policyStore)))

	// Required mutable root attributes
	sb.WriteString(fmt.Sprintf("  DisplayName = %s\n", psQuote(input.DisplayName)))
	sb.WriteString(fmt.Sprintf("  Direction   = %s\n", psQuote(input.Direction)))
	sb.WriteString(fmt.Sprintf("  Action      = %s\n", psQuote(input.Action)))

	// Optional root attributes
	if input.Description != "" {
		sb.WriteString(fmt.Sprintf("  Description = %s\n", psQuote(input.Description)))
	}
	if input.Enabled != nil {
		// -Enabled is the NetSecurity.Enabled enum, not a [bool]: PowerShell
		// rejects $true/$false and requires the "True"/"False" string tokens.
		if *input.Enabled {
			sb.WriteString("  Enabled = 'True'\n")
		} else {
			sb.WriteString("  Enabled = 'False'\n")
		}
	}
	if len(input.Profile) > 0 {
		sb.WriteString(fmt.Sprintf("  Profile = %s\n", psQuoteList(input.Profile)))
	}
	if input.EdgeTraversalPolicy != "" {
		sb.WriteString(fmt.Sprintf("  EdgeTraversalPolicy = %s\n", psQuote(input.EdgeTraversalPolicy)))
	}
	// Group is ForceNew; only written on Create (Set-NetFirewallRule ignores it).
	if op == "create" && input.Group != "" {
		sb.WriteString(fmt.Sprintf("  Group = %s\n", psQuote(input.Group)))
	}

	// Filter attributes
	if input.Protocol != "" {
		sb.WriteString(fmt.Sprintf("  Protocol = %s\n", psQuote(input.Protocol)))
	}
	if len(input.LocalPort) > 0 {
		sb.WriteString(fmt.Sprintf("  LocalPort = %s\n", psQuoteList(input.LocalPort)))
	}
	if len(input.RemotePort) > 0 {
		sb.WriteString(fmt.Sprintf("  RemotePort = %s\n", psQuoteList(input.RemotePort)))
	}
	if len(input.LocalAddress) > 0 {
		sb.WriteString(fmt.Sprintf("  LocalAddress = %s\n", psQuoteList(input.LocalAddress)))
	}
	if len(input.RemoteAddress) > 0 {
		sb.WriteString(fmt.Sprintf("  RemoteAddress = %s\n", psQuoteList(input.RemoteAddress)))
	}
	if input.Program != "" {
		sb.WriteString(fmt.Sprintf("  Program = %s\n", psQuote(input.Program)))
	}
	if input.Service != "" {
		sb.WriteString(fmt.Sprintf("  Service = %s\n", psQuote(input.Service)))
	}
	if input.InterfaceType != "" {
		sb.WriteString(fmt.Sprintf("  InterfaceType = %s\n", psQuote(input.InterfaceType)))
	}

	sb.WriteString("}")
	return sb.String()
}

// runFirewallEnvelope executes script (prefixed with frPsHeader) and returns
// the parsed psResponse envelope. Transport/PS-level errors that bypass
// Emit-Err are translated into *FirewallRuleError.
func (c *FirewallRuleClient) runFirewallEnvelope(ctx context.Context, op, name, script string) (*psResponse, error) {
	full := frPsHeader + "\n" + script
	stdout, stderr, err := runPowerShell(ctx, c.c, full)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, NewFirewallRuleError(
				FirewallRuleErrorUnknown,
				fmt.Sprintf("operation %q timed out or was cancelled", op),
				ctxErr,
				map[string]string{"operation": op, "name": name, "host": c.c.cfg.Host},
			)
		}
		return nil, NewFirewallRuleError(
			FirewallRuleErrorUnknown,
			fmt.Sprintf("PowerShell transport error during %q", op),
			err,
			map[string]string{
				"operation": op, "name": name, "host": c.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		)
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewFirewallRuleError(
			FirewallRuleErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op),
			nil,
			map[string]string{
				"operation": op, "name": name, "host": c.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		)
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewFirewallRuleError(
			FirewallRuleErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op),
			jerr,
			map[string]string{
				"operation": op, "name": name, "host": c.c.cfg.Host,
				"stdout": truncate(stdout, 2048),
			},
		)
	}

	if !resp.OK {
		kind := mapFirewallKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["name"] = name
		ctxMap["host"] = c.c.cfg.Host
		return &resp, NewFirewallRuleError(kind, resp.Message, nil, ctxMap)
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// frStateJSON - mirrors the JSON emitted by frReadBody
// ---------------------------------------------------------------------------

type frStateJSON struct {
	Name                string   `json:"name"`
	DisplayName         string   `json:"display_name"`
	Description         string   `json:"description"`
	Enabled             bool     `json:"enabled"`
	Direction           string   `json:"direction"`
	Action              string   `json:"action"`
	Profile             []string `json:"profile"`
	EdgeTraversalPolicy string   `json:"edge_traversal_policy"`
	Group               string   `json:"group"`
	PolicyStore         string   `json:"policy_store"`
	Protocol            string   `json:"protocol"`
	LocalPort           []string `json:"local_port"`
	RemotePort          []string `json:"remote_port"`
	LocalAddress        []string `json:"local_address"`
	RemoteAddress       []string `json:"remote_address"`
	Program             string   `json:"program"`
	Service             string   `json:"service"`
	InterfaceType       string   `json:"interface_type"`
}

// normaliseStrArr ensures a nil/empty slice becomes ["Any"] (ADR-FR-6).
func normaliseStrArr(s []string) []string {
	if len(s) == 0 {
		return []string{"Any"}
	}
	return s
}

// parseFirewallRuleState parses the psResponse.Data field into a
// *FirewallRuleState. Returns (nil, nil) when Data is JSON null (rule gone).
func parseFirewallRuleState(resp *psResponse, policyStore string) (*FirewallRuleState, error) {
	if resp.Data == nil || string(resp.Data) == "null" {
		return nil, nil
	}
	var j frStateJSON
	if err := json.Unmarshal(resp.Data, &j); err != nil {
		return nil, NewFirewallRuleError(
			FirewallRuleErrorUnknown,
			"failed to parse firewall rule state JSON",
			err,
			map[string]string{"raw": truncate(string(resp.Data), 512)},
		)
	}
	// Fallback: if policy_store was absent from the JSON use the caller's value.
	store := j.PolicyStore
	if store == "" {
		store = policyStore
	}
	return &FirewallRuleState{
		Name:                j.Name,
		DisplayName:         j.DisplayName,
		Description:         j.Description,
		Enabled:             j.Enabled,
		Direction:           j.Direction,
		Action:              j.Action,
		Profile:             normaliseStrArr(j.Profile),
		EdgeTraversalPolicy: j.EdgeTraversalPolicy,
		Group:               j.Group,
		PolicyStore:         store,
		Protocol:            j.Protocol,
		LocalPort:           normaliseStrArr(j.LocalPort),
		RemotePort:          normaliseStrArr(j.RemotePort),
		LocalAddress:        normaliseStrArr(j.LocalAddress),
		RemoteAddress:       normaliseStrArr(j.RemoteAddress),
		Program:             j.Program,
		Service:             j.Service,
		InterfaceType:       j.InterfaceType,
	}, nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// Create adds a new Windows Defender Firewall rule via New-NetFirewallRule,
// then calls Read to populate all computed filter attributes.
func (c *FirewallRuleClient) Create(ctx context.Context, input FirewallRuleInput) (*FirewallRuleState, error) {
	if err := checkWritableStore(input.PolicyStore); err != nil {
		return nil, err
	}

	params := buildFirewallParams("create", input.Name, input.PolicyStore, input)
	script := strings.NewReplacer(
		"@@NAME@@", psQuote(input.Name),
		"@@PSTORE@@", psQuote(input.PolicyStore),
		"@@PARAMS@@", params,
	).Replace(frCreateBody)

	if _, err := c.runFirewallEnvelope(ctx, "Create", input.Name, script); err != nil {
		return nil, err
	}

	return c.Read(ctx, input.Name, input.PolicyStore)
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// Read retrieves the current state of the named firewall rule using
// Get-NetFirewallRule piped into all associated Get-NetFirewall*Filter cmdlets.
// Returns (nil, nil) when the rule does not exist (ItemNotFoundException).
func (c *FirewallRuleClient) Read(ctx context.Context, name, policyStore string) (*FirewallRuleState, error) {
	script := buildFirewallReplacer(name, policyStore).Replace(frReadBody)
	resp, err := c.runFirewallEnvelope(ctx, "Read", name, script)
	if err != nil {
		if IsFirewallRuleError(err, FirewallRuleErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseFirewallRuleState(resp, policyStore)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// Update applies in-place changes to an existing firewall rule via a single
// Set-NetFirewallRule call.
func (c *FirewallRuleClient) Update(ctx context.Context, name, policyStore string, input FirewallRuleInput) (*FirewallRuleState, error) {
	if err := checkWritableStore(policyStore); err != nil {
		return nil, err
	}

	params := buildFirewallParams("update", name, policyStore, input)
	script := strings.NewReplacer(
		"@@NAME@@", psQuote(name),
		"@@PSTORE@@", psQuote(policyStore),
		"@@PARAMS@@", params,
	).Replace(frUpdateBody)

	if _, err := c.runFirewallEnvelope(ctx, "Update", name, script); err != nil {
		return nil, err
	}

	return c.Read(ctx, name, policyStore)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// Delete removes the firewall rule via Remove-NetFirewallRule.
// ItemNotFoundException is treated as success (idempotency).
func (c *FirewallRuleClient) Delete(ctx context.Context, name, policyStore string) error {
	if err := checkWritableStore(policyStore); err != nil {
		return err
	}

	script := buildFirewallReplacer(name, policyStore).Replace(frDeleteBody)
	_, err := c.runFirewallEnvelope(ctx, "Delete", name, script)
	return err
}
