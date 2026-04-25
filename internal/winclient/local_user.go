// Package winclient provides the PowerShell/WinRM-backed implementation of
// LocalUserClient for managing Windows local user accounts.
//
// Security invariants:
//   - Passwords are NEVER interpolated into script bodies. They are injected
//     via stdin (runLUEnvelopeWithInput) and read by the PS script via
//     [Console]::In.ReadLine(). This prevents the plaintext from appearing in
//     WinRM -EncodedCommand payloads, trace logs, or diagnostic output.
//   - All other user-supplied strings are escaped via psQuote (single-quoted
//     PowerShell literals with embedded quotes doubled).
//   - No secret appears in LocalUserError.Message or Context.
//
// Reused helpers from service.go (same package):
//   - psQuote            — safe single-quote escaping
//   - extractLastJSONLine — scan stdout for last JSON envelope
//   - truncate            — cap strings for diagnostic context
//   - runPowerShell       — package-level hook for testability
//   - psResponse          — parsed Emit-OK / Emit-Err JSON envelope
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: LocalUserClientImpl satisfies LocalUserClient.
var _ LocalUserClient = (*LocalUserClientImpl)(nil)

// LocalUserClientImpl is the PowerShell/WinRM-backed LocalUserClient.
type LocalUserClientImpl struct {
	c *Client
}

// NewLocalUserClient constructs a LocalUserClientImpl wrapping the given WinRM Client.
func NewLocalUserClient(c *Client) *LocalUserClientImpl {
	return &LocalUserClientImpl{c: c}
}

// runPSInput is the package-level hook for stdin-based PowerShell execution.
// Tests can override this to inject fake responses without a real WinRM connection.
var runPSInput = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	return c.RunPowerShellWithInput(ctx, script, stdin)
}

// ---------------------------------------------------------------------------
// PowerShell header — Emit-OK, Emit-Err, Classify-LU, Format-PSDate, Get-UserData
// ---------------------------------------------------------------------------

// luPsHeader is prepended to every local-user script. It defines:
//
//   - Emit-OK / Emit-Err : JSON envelope emitters.
//   - Classify-LU        : maps PowerShell LocalAccounts exception identifiers
//     to LocalUserErrorKind strings for locale-independent error handling.
//   - Format-PSDate      : normalises DateTimeOffset/DateTime to RFC3339 or $null.
//   - Get-UserData       : builds the normalised JSON hashtable from a LocalUser object.
//
// NOTE: this constant uses a Go raw string (backtick-delimited). PowerShell
// backtick escape sequences (`n, `t) MUST NOT appear in this body.
const luPsHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  $json = ($obj | ConvertTo-Json -Depth 8 -Compress)
  [Console]::Out.WriteLine($json)
}

function Classify-LU([string]$Msg, [string]$FQEI) {
  if ($FQEI -match 'UserNotFound' -or $Msg -match 'was not found') { return 'not_found' }
  if ($FQEI -match 'UserExists' -or $Msg -match 'already exists') { return 'already_exists' }
  if ($FQEI -match 'UserNameExists' -or $Msg -match 'not unique') { return 'rename_conflict' }
  if ($FQEI -match 'AccessDenied' -or $Msg -match 'Access is denied') { return 'permission_denied' }
  if ($FQEI -match 'InvalidPassword' -or $Msg -match 'password' -or $Msg -match 'Password' -or $Msg -match 'complexity' -or $Msg -match 'minimum length') { return 'password_policy' }
  if ($FQEI -match 'InvalidName' -or $Msg -match 'invalid.*name') { return 'invalid_name' }
  return 'unknown'
}

function Format-PSDate($dt) {
  if ($null -eq $dt) { return $null }
  $d = $null
  if ($dt -is [DateTimeOffset]) { $d = $dt.UtcDateTime }
  elseif ($dt -is [DateTime]) { $d = $dt.ToUniversalTime() }
  else { return $null }
  if ($d.Year -le 1 -or $d.Year -ge 9999) { return $null }
  return $d.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-UserData($User) {
  return [ordered]@{
    Name                  = $User.Name
    FullName              = if ($null -eq $User.FullName) { '' } else { $User.FullName }
    Description           = if ($null -eq $User.Description) { '' } else { $User.Description }
    Enabled               = $User.Enabled
    PasswordNeverExpires  = $User.PasswordNeverExpires
    UserMayChangePassword = $User.UserMayChangePassword
    AccountExpires        = (Format-PSDate $User.AccountExpires)
    LastLogon             = (Format-PSDate $User.LastLogon)
    PasswordLastSet       = (Format-PSDate $User.PasswordLastSet)
    PrincipalSource       = [string]$User.PrincipalSource
    SID                   = $User.SID.Value
  }
}
`

// ---------------------------------------------------------------------------
// psLocalUser — JSON shape of the normalised user hashtable
// ---------------------------------------------------------------------------

// psLocalUser is the Go-side representation of the JSON hashtable produced by
// Get-UserData in the PowerShell scripts. All dates are RFC3339 strings or null.
type psLocalUser struct {
	Name                  string  `json:"Name"`
	FullName              string  `json:"FullName"`
	Description           string  `json:"Description"`
	Enabled               bool    `json:"Enabled"`
	PasswordNeverExpires  bool    `json:"PasswordNeverExpires"`
	UserMayChangePassword bool    `json:"UserMayChangePassword"` // positive form; inverted for TF
	AccountExpires        *string `json:"AccountExpires"`        // null ⇒ never expires
	LastLogon             *string `json:"LastLogon"`             // null ⇒ never logged on
	PasswordLastSet       *string `json:"PasswordLastSet"`       // null ⇒ not set
	PrincipalSource       string  `json:"PrincipalSource"`
	SID                   string  `json:"SID"`
}

// ---------------------------------------------------------------------------
// mapLUKind / parseUserData — helpers
// ---------------------------------------------------------------------------

// mapLUKind converts a PS-emitted kind string to a LocalUserErrorKind constant.
func mapLUKind(k string) LocalUserErrorKind {
	switch k {
	case "not_found":
		return LocalUserErrorNotFound
	case "already_exists":
		return LocalUserErrorAlreadyExists
	case "builtin_account":
		return LocalUserErrorBuiltinAccount
	case "rename_conflict":
		return LocalUserErrorRenameConflict
	case "password_policy":
		return LocalUserErrorPasswordPolicy
	case "permission_denied":
		return LocalUserErrorPermission
	case "invalid_name":
		return LocalUserErrorInvalidName
	default:
		return LocalUserErrorUnknown
	}
}

// parseUserData deserialises the Data field of a psResponse into a *UserState.
func parseUserData(op string, data json.RawMessage) (*UserState, error) {
	var u psLocalUser
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			fmt.Sprintf("failed to parse LocalUser JSON from %q", op), err, nil)
	}
	if u.SID == "" {
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			fmt.Sprintf("LocalUser JSON from %q has empty SID", op), nil, nil)
	}

	st := &UserState{
		Name:                     u.Name,
		FullName:                 u.FullName,
		Description:              u.Description,
		Enabled:                  u.Enabled,
		PasswordNeverExpires:     u.PasswordNeverExpires,
		UserMayNotChangePassword: !u.UserMayChangePassword, // invert: Windows positive → TF negative
		SID:                      u.SID,
		PrincipalSource:          u.PrincipalSource,
	}

	// AccountExpires: null ⇒ account never expires.
	if u.AccountExpires != nil {
		st.AccountExpires = *u.AccountExpires
		st.AccountNeverExpires = false
	} else {
		st.AccountExpires = ""
		st.AccountNeverExpires = true
	}

	// LastLogon: null ⇒ empty string (never logged on).
	if u.LastLogon != nil {
		st.LastLogon = *u.LastLogon
	}

	// PasswordLastSet: null ⇒ empty string (not yet set).
	if u.PasswordLastSet != nil {
		st.PasswordLastSet = *u.PasswordLastSet
	}

	return st, nil
}

// ---------------------------------------------------------------------------
// runLUEnvelope / runLUEnvelopeWithInput — execute + parse JSON envelope
// ---------------------------------------------------------------------------

// runLUEnvelope executes script (prefixed with luPsHeader) and parses the
// Emit-OK / Emit-Err JSON envelope. op is a diagnostic label; key is the
// primary identifier (SID or name) used in error context.
func (lc *LocalUserClientImpl) runLUEnvelope(ctx context.Context, op, key, script string) (*psResponse, error) {
	full := luPsHeader + "\n" + script
	stdout, stderr, err := runPowerShell(ctx, lc.c, full)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewLocalUserError(LocalUserErrorUnknown,
				fmt.Sprintf("operation %q timed out or was cancelled", op),
				ctx.Err(), map[string]string{
					"operation": op, "key": key, "host": lc.c.cfg.Host,
				})
		}
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			fmt.Sprintf("WinRM transport error during %q", op),
			err, map[string]string{
				"operation": op, "key": key, "host": lc.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}
	return lc.parseLUEnvelope(op, key, stdout, stderr)
}

// runLUEnvelopeWithInput executes script (prefixed with luPsHeader) with the
// given stdin string (used for password injection) and parses the JSON envelope.
// The stdin value is NEVER included in error context or logs.
func (lc *LocalUserClientImpl) runLUEnvelopeWithInput(ctx context.Context, op, key, script, stdin string) (*psResponse, error) {
	full := luPsHeader + "\n" + script
	stdout, stderr, err := runPSInput(ctx, lc.c, full, stdin)
	if err != nil {
		if ctx.Err() != nil {
			return nil, NewLocalUserError(LocalUserErrorUnknown,
				fmt.Sprintf("operation %q timed out or was cancelled", op),
				ctx.Err(), map[string]string{
					"operation": op, "key": key, "host": lc.c.cfg.Host,
				})
		}
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			fmt.Sprintf("WinRM transport error during %q", op),
			err, map[string]string{
				"operation": op, "key": key, "host": lc.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}
	return lc.parseLUEnvelope(op, key, stdout, stderr)
}

// parseLUEnvelope extracts the last JSON line from stdout and unmarshals the
// Emit-OK / Emit-Err envelope. Returns a *LocalUserError on failure.
func (lc *LocalUserClientImpl) parseLUEnvelope(op, key, stdout, stderr string) (*psResponse, error) {
	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op), nil,
			map[string]string{
				"operation": op, "key": key, "host": lc.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	var resp psResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewLocalUserError(LocalUserErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op), jerr,
			map[string]string{
				"operation": op, "key": key, "host": lc.c.cfg.Host,
				"stdout": truncate(stdout, 2048),
			})
	}

	if !resp.OK {
		kind := mapLUKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["key"] = key
		ctxMap["host"] = lc.c.cfg.Host
		return &resp, NewLocalUserError(kind, resp.Message, nil, ctxMap)
	}
	return &resp, nil
}

// ---------------------------------------------------------------------------
// Create — EC-1 pre-flight + module guard (ADR-LU-1)
// ---------------------------------------------------------------------------

// Create creates a new Windows local user account.
//
// Steps:
//  1. Module availability guard.
//  2. Pre-flight name collision check (EC-1).
//  3. Read password from stdin inside the PS script (ADR-LU-3).
//  4. Call New-LocalUser with all applicable parameters.
//  5. Re-read the account via Get-LocalUser -SID to get the full state.
func (lc *LocalUserClientImpl) Create(ctx context.Context, input UserInput, password string) (*UserState, error) {
	qName := psQuote(input.Name)
	qFullName := psQuote(input.FullName)
	qDesc := psQuote(input.Description)

	// Build optional splatting additions.
	var optParts strings.Builder
	if input.FullName != "" {
		optParts.WriteString("\n    $params['FullName'] = " + qFullName)
	}
	if input.Description != "" {
		optParts.WriteString("\n    $params['Description'] = " + qDesc)
	}
	if input.PasswordNeverExpires {
		optParts.WriteString("\n    $params['PasswordNeverExpires'] = $true")
	}
	if input.UserMayNotChangePassword {
		optParts.WriteString("\n    $params['UserMayNotChangePassword'] = $true")
	}
	if !input.Enabled {
		optParts.WriteString("\n    $params['Disabled'] = $true")
	}
	if input.AccountNeverExpires {
		optParts.WriteString("\n    $params['AccountNeverExpires'] = $true")
	} else if input.AccountExpires != "" {
		optParts.WriteString("\n    $params['AccountExpires'] = [DateTimeOffset]::Parse(" + psQuote(input.AccountExpires) + ").UtcDateTime")
	}

	script := fmt.Sprintf(`
# Module guard
if (-not (Get-Command New-LocalUser -ErrorAction SilentlyContinue)) {
    Emit-Err 'unknown' 'Microsoft.PowerShell.LocalAccounts module not available; requires Windows Server 2016 / Windows 10 or later' @{}
    return
}

# Pre-flight: name collision check (EC-1)
try {
    $existing = Get-LocalUser -Name %s -ErrorAction Stop
    Emit-Err 'already_exists' ("local user '%s' already exists on this host (SID: " + $existing.SID.Value + "); use 'terraform import' to bring it under management instead of creating a duplicate") @{ sid = $existing.SID.Value; name = $existing.Name }
    return
} catch {
    $fq = $_.FullyQualifiedErrorId
    if ($fq -notmatch 'UserNotFound' -and $_.Exception.Message -notmatch 'was not found') {
        $kind = Classify-LU $_.Exception.Message $fq
        Emit-Err $kind $_.Exception.Message @{ name = %s; step = 'preflight_read' }
        return
    }
}

# Read password from stdin (plaintext never in script body, ADR-LU-3)
$PlainPassword = [Console]::In.ReadLine()
$SecurePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force

# Create user
try {
    $params = @{ Name = %s; Password = $SecurePassword; ErrorAction = 'Stop' }%s
    $user = New-LocalUser @params
    $freshUser = Get-LocalUser -SID $user.SID.Value -ErrorAction Stop
    $data = Get-UserData $freshUser
    Emit-OK $data
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ name = %s; step = 'new_local_user' }
}
`,
		qName, input.Name, qName,
		qName, optParts.String(),
		qName)

	// Inject password via stdin (never appears in script body or logs).
	resp, err := lc.runLUEnvelopeWithInput(ctx, "create", input.Name, script, password+"\n")
	if err != nil {
		return nil, err
	}
	return parseUserData("create", resp.Data)
}

// ---------------------------------------------------------------------------
// Read — EC-3 (UserNotFound → nil, nil)
// ---------------------------------------------------------------------------

// Read retrieves the current state of the user identified by sid.
// Returns (nil, nil) when the user does not exist (EC-3 drift detection).
func (lc *LocalUserClientImpl) Read(ctx context.Context, sid string) (*UserState, error) {
	qSID := psQuote(sid)

	script := fmt.Sprintf(`
try {
    $user = Get-LocalUser -SID %s -ErrorAction Stop
    $data = Get-UserData $user
    Emit-OK $data
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'get_local_user' }
}
`, qSID, qSID)

	resp, err := lc.runLUEnvelope(ctx, "read", sid, script)
	if err != nil {
		// EC-3: user disappeared outside Terraform — not an error.
		if IsLocalUserError(err, LocalUserErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseUserData("read", resp.Data)
}

// ---------------------------------------------------------------------------
// Update — Set-LocalUser scalar attributes
// ---------------------------------------------------------------------------

// Update applies scalar attribute changes to the user identified by sid via
// Set-LocalUser. Does NOT handle renames (use Rename), passwords (use SetPassword),
// or enabled state (use Enable/Disable).
//
// PasswordNeverExpires and UserMayNotChangePassword are always passed as
// explicit booleans (Set-LocalUser accepts $true/$false for these).
func (lc *LocalUserClientImpl) Update(ctx context.Context, sid string, input UserInput) (*UserState, error) {
	qSID := psQuote(sid)
	qFullName := psQuote(input.FullName)
	qDesc := psQuote(input.Description)

	pne := "$false"
	if input.PasswordNeverExpires {
		pne = "$true"
	}
	umcp := "$false"
	if input.UserMayNotChangePassword {
		umcp = "$true"
	}

	var expiryBlock string
	if input.AccountNeverExpires {
		expiryBlock = "$params['AccountNeverExpires'] = $true"
	} else if input.AccountExpires != "" {
		expiryBlock = "$params['AccountExpires'] = [DateTimeOffset]::Parse(" + psQuote(input.AccountExpires) + ").UtcDateTime"
	} else {
		expiryBlock = "# account expiry: no change requested"
	}

	script := fmt.Sprintf(`
try {
    $params = @{
        SID = %s
        FullName = %s
        Description = %s
        PasswordNeverExpires = %s
        UserMayNotChangePassword = %s
        ErrorAction = 'Stop'
    }
    %s
    Set-LocalUser @params
    $user = Get-LocalUser -SID %s -ErrorAction Stop
    $data = Get-UserData $user
    Emit-OK $data
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'set_local_user' }
}
`, qSID, qFullName, qDesc, pne, umcp, expiryBlock, qSID, qSID)

	resp, err := lc.runLUEnvelope(ctx, "update", sid, script)
	if err != nil {
		return nil, err
	}
	return parseUserData("update", resp.Data)
}

// ---------------------------------------------------------------------------
// Rename — Rename-LocalUser -SID (EC-5)
// ---------------------------------------------------------------------------

// Rename renames the user via Rename-LocalUser -SID -NewName.
// The SID is unchanged; must be called BEFORE Update in the same apply.
func (lc *LocalUserClientImpl) Rename(ctx context.Context, sid, newName string) error {
	qSID := psQuote(sid)
	qName := psQuote(newName)

	script := fmt.Sprintf(`
try {
    Rename-LocalUser -SID %s -NewName %s -ErrorAction Stop
    Emit-OK @{ renamed = $true }
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; new_name = %s; step = 'rename_local_user' }
}
`, qSID, qName, qSID, qName)

	_, err := lc.runLUEnvelope(ctx, "rename", sid, script)
	return err
}

// ---------------------------------------------------------------------------
// SetPassword — password via stdin (EC-6, ADR-LU-3)
// ---------------------------------------------------------------------------

// SetPassword rotates the account password via Set-LocalUser -SID -Password.
// The password plaintext is injected via stdin and NEVER appears in the script
// body, WinRM trace logs, or diagnostic output (ADR-LU-3, EC-6).
func (lc *LocalUserClientImpl) SetPassword(ctx context.Context, sid, password string) error {
	qSID := psQuote(sid)

	script := fmt.Sprintf(`
# Read password from stdin (plaintext never in script body, ADR-LU-3)
$PlainPassword = [Console]::In.ReadLine()
$SecurePassword = ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
try {
    Set-LocalUser -SID %s -Password $SecurePassword -ErrorAction Stop
    Emit-OK @{ password_set = $true }
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'set_password' }
}
`, qSID, qSID)

	_, err := lc.runLUEnvelopeWithInput(ctx, "set_password", sid, script, password+"\n")
	return err
}

// ---------------------------------------------------------------------------
// Enable / Disable
// ---------------------------------------------------------------------------

// Enable enables the account via Enable-LocalUser -SID.
func (lc *LocalUserClientImpl) Enable(ctx context.Context, sid string) error {
	qSID := psQuote(sid)
	script := fmt.Sprintf(`
try {
    Enable-LocalUser -SID %s -ErrorAction Stop
    Emit-OK @{ enabled = $true }
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'enable_local_user' }
}
`, qSID, qSID)
	_, err := lc.runLUEnvelope(ctx, "enable", sid, script)
	return err
}

// Disable disables the account via Disable-LocalUser -SID.
func (lc *LocalUserClientImpl) Disable(ctx context.Context, sid string) error {
	qSID := psQuote(sid)
	script := fmt.Sprintf(`
try {
    Disable-LocalUser -SID %s -ErrorAction Stop
    Emit-OK @{ disabled = $true }
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'disable_local_user' }
}
`, qSID, qSID)
	_, err := lc.runLUEnvelope(ctx, "disable", sid, script)
	return err
}

// ---------------------------------------------------------------------------
// Delete — EC-2 built-in RID guard + Remove-LocalUser
// ---------------------------------------------------------------------------

// Delete removes the Windows local user identified by sid.
//
// Pre-flight: if the SID's RID (last numeric component) is 500, 501, 503, or
// 504 (built-in accounts Administrator / Guest / DefaultAccount /
// WDAGUtilityAccount), returns ErrLocalUserBuiltinAccount immediately without
// calling Remove-LocalUser (EC-2, ADR-LU-2). This check is immune to renames.
func (lc *LocalUserClientImpl) Delete(ctx context.Context, sid string) error {
	// EC-2: built-in RID guard.
	parts := strings.Split(sid, "-")
	if len(parts) > 0 {
		rid := parts[len(parts)-1]
		switch rid {
		case "500", "501", "503", "504":
			name := sid
			if us, readErr := lc.Read(ctx, sid); readErr == nil && us != nil {
				name = us.Name
			}
			return NewLocalUserError(LocalUserErrorBuiltinAccount,
				fmt.Sprintf(
					"cannot destroy built-in local user %q (SID: %s, RID: %s); "+
						"use 'terraform state rm' to remove this resource from state "+
						"without deleting the account",
					name, sid, rid,
				),
				nil, map[string]string{"sid": sid, "name": name, "rid": rid},
			)
		}
	}

	qSID := psQuote(sid)
	script := fmt.Sprintf(`
try {
    Remove-LocalUser -SID %s -ErrorAction Stop
    Emit-OK @{ deleted = $true }
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    if ($kind -eq 'not_found') {
        Emit-OK @{ deleted = $true; note = 'already_absent' }
        return
    }
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'remove_local_user' }
}
`, qSID, qSID)

	_, err := lc.runLUEnvelope(ctx, "delete", sid, script)
	return err
}

// ---------------------------------------------------------------------------
// ImportByName / ImportBySID — EC-11
// ---------------------------------------------------------------------------

// ImportByName resolves a local user by SAM name (non-SID import path).
// Returns ErrLocalUserNotFound when no user with the given name exists.
func (lc *LocalUserClientImpl) ImportByName(ctx context.Context, name string) (*UserState, error) {
	qName := psQuote(name)
	script := fmt.Sprintf(`
try {
    $user = Get-LocalUser -Name %s -ErrorAction Stop
    $data = Get-UserData $user
    Emit-OK $data
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ name = %s; step = 'import_by_name' }
}
`, qName, qName)

	resp, err := lc.runLUEnvelope(ctx, "import_by_name", name, script)
	if err != nil {
		return nil, err
	}
	return parseUserData("import_by_name", resp.Data)
}

// ImportBySID resolves a local user by SID string (SID import path).
// Returns ErrLocalUserNotFound when no user with the given SID exists.
func (lc *LocalUserClientImpl) ImportBySID(ctx context.Context, sid string) (*UserState, error) {
	qSID := psQuote(sid)
	script := fmt.Sprintf(`
try {
    $user = Get-LocalUser -SID %s -ErrorAction Stop
    $data = Get-UserData $user
    Emit-OK $data
} catch {
    $kind = Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId
    Emit-Err $kind $_.Exception.Message @{ sid = %s; step = 'import_by_sid' }
}
`, qSID, qSID)

	resp, err := lc.runLUEnvelope(ctx, "import_by_sid", sid, script)
	if err != nil {
		return nil, err
	}
	return parseUserData("import_by_sid", resp.Data)
}
