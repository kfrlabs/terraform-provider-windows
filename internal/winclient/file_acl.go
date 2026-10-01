// Package winclient: windows_file_acl CRUD implementation over SSH.
//
// Transport invariants:
//   - The desired security descriptor travels as a single JSON document on
//     stdin (RunPowerShellWithInput), read back with [Console]::In.ReadToEnd()
//     and ConvertFrom-Json. ACL data is therefore data, never script text: no
//     identity, path or right ever reaches the parser as code. Only Read, which
//     takes nothing but a path, interpolates through psQuote.
//   - Errors are classified from .NET exception types and Win32 codes read from
//     HResult, never from message text, so the mapping survives a non-English
//     target host.
//
// Convergence invariant (authoritative mode): protecting a target while
// preserving its inherited entries cannot converge, so it is not attempted.
//
// Verified on a live host: SetAccessRuleProtection(true, true) does not convert
// the inherited entries in memory. GetAccessRules reports zero explicit entries
// immediately afterwards, because the conversion is performed by the kernel when
// Set-Acl commits. The copies therefore land on disk as explicit entries that
// the purge of this same pass never saw, and the next apply removes them: two
// consecutive applies never reach a fixed point.
//
// ValidateFileACLInput consequently forces PreserveInheritedOnProtect to false
// whenever authoritative mode protects a target, which makes the resulting DACL
// exactly the declared rules. The flag keeps its meaning in additive mode, where
// undeclared entries are not managed and the preserved copies are stable.
//
// Protection is still applied before the purge, so a target that is becoming
// unprotected has its stale explicit entries removed in the same pass.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: FileACLClientImpl satisfies FileACLClient.
var _ FileACLClient = (*FileACLClientImpl)(nil)

// FileACLClientImpl is the PowerShell/SSH-backed FileACLClient.
type FileACLClientImpl struct {
	c *Client
}

// NewFileACLClient constructs a FileACLClientImpl wrapping the given SSH Client.
func NewFileACLClient(c *Client) *FileACLClientImpl {
	return &FileACLClientImpl{c: c}
}

// runFileACLPowerShell is the seam unit tests replace to avoid any SSH.
var runFileACLPowerShell = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	if stdin == "" {
		return c.RunPowerShell(ctx, script)
	}
	return c.RunPowerShellWithInput(ctx, script, stdin)
}

// psFileACLHeader holds every PowerShell helper shared by the ACL scripts.
const psFileACLHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

function Emit-OK([object]$Data) {
  $obj = [ordered]@{ ok = $true; data = $Data }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 16 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if (-not $Ctx) { $Ctx = @{} }
  $obj = [ordered]@{ ok = $false; kind = $Kind; message = $Message; context = $Ctx }
  [Console]::Out.WriteLine(($obj | ConvertTo-Json -Depth 8 -Compress))
}

# Classify-FileACLError maps a .NET exception to a FileACLErrorKind. Win32 codes
# come from HResult rather than from message text so the mapping is immune to
# the locale of the target host.
function Classify-FileACLError($Rec) {
  $ex = $Rec.Exception
  while ($null -ne $ex -and $ex -is [System.Management.Automation.MethodInvocationException] -and $null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  if ($ex -is [System.Security.Principal.IdentityNotMappedException])  { return 'identity_not_found' }
  if ($ex -is [System.Security.AccessControl.PrivilegeNotHeldException]) { return 'privilege_not_held' }
  if ($ex -is [System.UnauthorizedAccessException])   { return 'permission_denied' }
  if ($ex -is [System.IO.DirectoryNotFoundException]) { return 'path_not_found' }
  if ($ex -is [System.IO.FileNotFoundException])      { return 'not_found' }
  if ($ex -is [System.ArgumentException])             { return 'invalid_input' }
  if ($ex -is [System.IO.IOException]) {
    $code = 0
    try { $code = [int]($ex.HResult -band 0xFFFF) } catch { $code = 0 }
    switch ($code) {
      2  { return 'not_found' }          # ERROR_FILE_NOT_FOUND
      3  { return 'path_not_found' }     # ERROR_PATH_NOT_FOUND
      5  { return 'permission_denied' }  # ERROR_ACCESS_DENIED
      32 { return 'file_locked' }        # ERROR_SHARING_VIOLATION
      33 { return 'file_locked' }        # ERROR_LOCK_VIOLATION
    }
    return 'unknown'
  }
  return 'unknown'
}

# Resolve-FileACLIdentity accepts a SID, a qualified name or a bare local name
# and always returns a SecurityIdentifier. A raw SID is NOT resolved through the
# account database: an orphaned SID left by a deleted account must stay usable.
function Resolve-FileACLIdentity([string]$Id) {
  if ($Id -match '^[Ss]-1-') {
    try {
      return (New-Object System.Security.Principal.SecurityIdentifier($Id))
    } catch {
      throw (New-Object System.ArgumentException(('not a valid SID: ' + $Id)))
    }
  }
  try {
    $acct = New-Object System.Security.Principal.NTAccount($Id)
    return $acct.Translate([System.Security.Principal.SecurityIdentifier])
  } catch {
    throw (New-Object System.Security.Principal.IdentityNotMappedException(('cannot resolve identity: ' + $Id)))
  }
}

function Get-FileACLTargetType([string]$P) {
  if ([System.IO.Directory]::Exists($P)) { return 'directory' }
  if ([System.IO.File]::Exists($P))      { return 'file' }
  return ''
}

function Get-FileACLInheritanceFlags([string]$V) {
  switch ($V) {
    'object'           { return [System.Security.AccessControl.InheritanceFlags]::ObjectInherit }
    'container'        { return [System.Security.AccessControl.InheritanceFlags]::ContainerInherit }
    'container_object' { return ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) }
    default            { return [System.Security.AccessControl.InheritanceFlags]::None }
  }
}

function Get-FileACLInheritanceName($F) {
  $c = [bool]([int]$F -band [int][System.Security.AccessControl.InheritanceFlags]::ContainerInherit)
  $o = [bool]([int]$F -band [int][System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
  if ($c -and $o) { return 'container_object' }
  if ($c)         { return 'container' }
  if ($o)         { return 'object' }
  return 'none'
}

function Get-FileACLPropagationFlags([string]$V) {
  switch ($V) {
    'inherit_only' { return [System.Security.AccessControl.PropagationFlags]::InheritOnly }
    'no_propagate' { return [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit }
    default        { return [System.Security.AccessControl.PropagationFlags]::None }
  }
}

function Get-FileACLPropagationName($F) {
  $n = [bool]([int]$F -band [int][System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)
  $i = [bool]([int]$F -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly)
  if ($n) { return 'no_propagate' }
  if ($i) { return 'inherit_only' }
  return 'none'
}

# New-FileACLRule builds a FileSystemAccessRule from one JSON rule object.
# An absent inheritance defaults per target type, which is the only place where
# the target type is actually known. Container inheritance on a file is refused
# rather than silently written as a no-op flag.
# access_mask arrives as an unsigned 32-bit value (JSON has no uint32): values
# above [int]::MaxValue must be folded back to signed before the
# FileSystemRights cast, otherwise a mask carrying generic rights fails.
function New-FileACLRule($Spec, [string]$TargetType) {
  $sid = Resolve-FileACLIdentity ([string]$Spec.identity)
  $inh = [string]$Spec.inheritance
  if ([string]::IsNullOrEmpty($inh)) {
    if ($TargetType -eq 'directory') { $inh = 'container_object' } else { $inh = 'none' }
  }
  if ($TargetType -eq 'file' -and $inh -ne 'none') {
    throw (New-Object System.ArgumentException(
      ('inheritance ' + $inh + ' is only valid on a directory; the target is a file')))
  }
  $maskLong = [int64]$Spec.access_mask
  if ($maskLong -gt 2147483647) { $maskLong = $maskLong - 4294967296 }
  $mask  = [int]$maskLong
  $type  = [System.Security.AccessControl.AccessControlType]::Allow
  if ([string]$Spec.type -eq 'deny') { $type = [System.Security.AccessControl.AccessControlType]::Deny }
  return (New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid,
    ([System.Security.AccessControl.FileSystemRights]$mask),
    (Get-FileACLInheritanceFlags $inh),
    (Get-FileACLPropagationFlags ([string]$Spec.propagation)),
    $type))
}

# Remove-FileACLRuleTolerant strips an ACE whether or not the host stored it
# with the Synchronize bit. RemoveAccessRuleSpecific requires an exact mask
# match, and the bit is not applied deterministically: a rule declared as Read
# (0x20089) lands as 0x20089 on a file but as 0x120089 on a directory. Trying
# only the declared mask would silently leave a stale ACE behind on every
# additive shrink.
function Remove-FileACLRuleTolerant($Acl, $Spec, [string]$TargetType) {
  [void]$Acl.RemoveAccessRuleSpecific((New-FileACLRule $Spec $TargetType))
  $alt = $Spec.PSObject.Copy()
  $alt.access_mask = ([int64]$Spec.access_mask -bor 1048576)
  [void]$Acl.RemoveAccessRuleSpecific((New-FileACLRule $alt $TargetType))
}

# Build-FileACLData re-reads the security descriptor and renders it as the JSON
# payload. Access rules are enumerated with SecurityIdentifier references so an
# unresolvable (orphaned) SID still yields a usable identity_sid; the display
# name is a best-effort translation that falls back to the SID string.
function Build-FileACLData([string]$P, [string]$T) {
  $acl = Get-Acl -LiteralPath $P
  $ownerSid  = ''
  $ownerName = ''
  try {
    $o = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if ($null -ne $o) {
      $ownerSid  = $o.Value
      $ownerName = $o.Value
      try { $ownerName = $o.Translate([System.Security.Principal.NTAccount]).Value } catch { }
    }
  } catch { }

  $rules = New-Object System.Collections.ArrayList
  foreach ($r in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    $sidValue = $r.IdentityReference.Value
    $name     = $sidValue
    try { $name = (New-Object System.Security.Principal.SecurityIdentifier($sidValue)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
    $kind = 'allow'
    if ($r.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) { $kind = 'deny' }
    # FileSystemRights is a signed int32 enum: generic rights (e.g. 0xE0000000
    # from an inherited parent ACE) read back as a negative [int], and
    # [uint32](negative) throws. Fold back to unsigned manually.
    $rawMask = [int]$r.FileSystemRights
    $maskU = [int64]$rawMask
    if ($rawMask -lt 0) { $maskU = $maskU + 4294967296 }
    [void]$rules.Add([ordered]@{
      identity     = $name
      identity_sid = $sidValue
      access_mask  = $maskU
      type         = $kind
      inheritance  = (Get-FileACLInheritanceName $r.InheritanceFlags)
      propagation  = (Get-FileACLPropagationName $r.PropagationFlags)
      inherited    = [bool]$r.IsInherited
    })
  }

  return [ordered]@{
    found               = $true
    path                = $P
    target_type         = $T
    owner               = $ownerName
    owner_sid           = $ownerSid
    inheritance_enabled = (-not $acl.AreAccessRulesProtected)
    sddl                = $acl.GetSecurityDescriptorSddlForm('All')
    access_rules        = ([object[]]$rules.ToArray())
  }
}
`

// psFileACLSetBody applies the desired descriptor. The whole input arrives as
// JSON on stdin; nothing is interpolated.
const psFileACLSetBody = `
& {
  $target = ''
  try {
    $spec   = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
    $target = [string]$spec.path
    $t = Get-FileACLTargetType $target
    if ($t -eq '') {
      Emit-Err 'not_found' ('target does not exist: ' + $target) @{ path = $target }
      return
    }

    $acl = Get-Acl -LiteralPath $target

    # Protection first: see the ordering invariant at the top of file_acl.go.
    $protect  = (-not [bool]$spec.inheritance_enabled)
    $preserve = [bool]$spec.preserve_inherited_on_protect
    $acl.SetAccessRuleProtection($protect, $preserve)

    if ([string]$spec.mode -eq 'authoritative') {
      foreach ($existing in @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))) {
        [void]$acl.RemoveAccessRuleSpecific($existing)
      }
    } else {
      # Additive: strip the previously managed rules so a shrinking rights list
      # actually takes effect, then re-add. Everything else is left alone.
      foreach ($prior in @($spec.prior_rules)) {
        if ($null -eq $prior) { continue }
        Remove-FileACLRuleTolerant $acl $prior $t
      }
    }

    foreach ($ar in @($spec.access_rules)) {
      if ($null -eq $ar) { continue }
      $acl.AddAccessRule((New-FileACLRule $ar $t))
    }

    $owner = [string]$spec.owner
    if (-not [string]::IsNullOrEmpty($owner)) {
      $ownerSid = Resolve-FileACLIdentity $owner
      try {
        $acl.SetOwner($ownerSid)
      } catch {
        Emit-Err 'privilege_not_held' ('cannot set owner to ' + $owner + ': ' + $_.Exception.Message) @{ path = $target; owner = $owner }
        return
      }
    }

    Set-Acl -LiteralPath $target -AclObject $acl
    Emit-OK (Build-FileACLData $target $t)
  } catch {
    Emit-Err (Classify-FileACLError $_) $_.Exception.Message @{ path = $target }
  }
}
`

// psFileACLReadBody returns the observed descriptor. Placeholder: @@PATH@@.
const psFileACLReadBody = `
& {
  $target = @@PATH@@
  try {
    $t = Get-FileACLTargetType $target
    if ($t -eq '') {
      Emit-OK @{ found = $false }
      return
    }
    Emit-OK (Build-FileACLData $target $t)
  } catch {
    Emit-Err (Classify-FileACLError $_) $_.Exception.Message @{ path = $target }
  }
}
`

// psFileACLResetBody restores inheritance and strips the managed explicit ACEs.
// It never deletes the target, and a missing target is a silent success.
const psFileACLResetBody = `
& {
  $target = ''
  try {
    $spec   = ([Console]::In.ReadToEnd() | ConvertFrom-Json)
    $target = [string]$spec.path
    $t = Get-FileACLTargetType $target
    if ($t -eq '') {
      Emit-OK @{ found = $false }
      return
    }
    $acl = Get-Acl -LiteralPath $target
    $acl.SetAccessRuleProtection($false, $false)
    foreach ($managed in @($spec.access_rules)) {
      if ($null -eq $managed) { continue }
      try { Remove-FileACLRuleTolerant $acl $managed $t }
      catch [System.Security.Principal.IdentityNotMappedException] {
        # The account was deleted after the ACE was written: nothing to strip
        # under that name, and the orphaned SID is handled by the caller.
        continue
      }
    }
    Set-Acl -LiteralPath $target -AclObject $acl
    Emit-OK @{ found = $true }
  } catch {
    Emit-Err (Classify-FileACLError $_) $_.Exception.Message @{ path = $target }
  }
}
`

// fileACLPSResponse is the parsed JSON envelope for ACL operations.
type fileACLPSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// fileACLDataPayload mirrors the JSON object returned by the scripts.
// AccessRules is json.RawMessage because ConvertTo-Json serialises a
// single-element array as a bare object.
type fileACLDataPayload struct {
	Found              bool            `json:"found"`
	Path               string          `json:"path"`
	TargetType         string          `json:"target_type"`
	Owner              string          `json:"owner"`
	OwnerSID           string          `json:"owner_sid"`
	InheritanceEnabled bool            `json:"inheritance_enabled"`
	SDDL               string          `json:"sddl"`
	AccessRules        json.RawMessage `json:"access_rules"`
}

// runScript executes a PS script and parses the JSON envelope.
func (f *FileACLClientImpl) runScript(ctx context.Context, op, script, stdin string) (*fileACLPSResponse, error) {
	stdout, stderr, err := runFileACLPowerShell(ctx, f.c, script, stdin)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &FileACLError{
				Kind:    FileACLErrorUnknown,
				Message: fmt.Sprintf("operation %q timed out or was cancelled", op),
				Cause:   ctxErr,
				Context: map[string]string{"operation": op, "host": f.c.cfg.Host},
			}
		}
		return nil, &FileACLError{
			Kind:    FileACLErrorUnknown,
			Message: fmt.Sprintf("SSH transport error during %q", op),
			Cause:   err,
			Context: map[string]string{
				"operation": op, "host": f.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		}
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, &FileACLError{
			Kind:    FileACLErrorUnknown,
			Message: fmt.Sprintf("no JSON envelope returned from %q", op),
			Context: map[string]string{
				"operation": op, "host": f.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		}
	}

	var resp fileACLPSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, &FileACLError{
			Kind:    FileACLErrorUnknown,
			Message: fmt.Sprintf("invalid JSON envelope from %q", op),
			Cause:   jerr,
			Context: map[string]string{"operation": op, "stdout": truncate(stdout, 2048)},
		}
	}

	if !resp.OK {
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["host"] = f.c.cfg.Host
		return &resp, &FileACLError{Kind: mapFileACLErrorKind(resp.Kind), Message: resp.Message, Context: ctxMap}
	}
	return &resp, nil
}

// mapFileACLErrorKind translates the PS-side "kind" string to a typed kind.
func mapFileACLErrorKind(k string) FileACLErrorKind {
	switch k {
	case string(FileACLErrorNotFound), string(FileACLErrorPathNotFound), string(FileACLErrorTypeConflict),
		string(FileACLErrorPermission), string(FileACLErrorPrivilegeNotHeld), string(FileACLErrorIdentityNotFound),
		string(FileACLErrorInvalidInput), string(FileACLErrorLocked):
		return FileACLErrorKind(k)
	default:
		return FileACLErrorUnknown
	}
}

// Set applies the desired security descriptor and returns the observed result.
func (f *FileACLClientImpl) Set(ctx context.Context, input FileACLInput) (*FileACLState, error) {
	if err := ValidateFileACLInput(&input); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, &FileACLError{Kind: FileACLErrorInvalidInput, Message: "cannot encode ACL specification", Cause: err}
	}
	script := psFileACLHeader + "\n" + psFileACLSetBody
	resp, err := f.runScript(ctx, "set", script, string(payload))
	if err != nil {
		return nil, err
	}
	return parseFileACLPayload(resp.Data, input.Path)
}

// Read returns the observed descriptor, or (nil, nil) when the target is absent.
func (f *FileACLClientImpl) Read(ctx context.Context, path string) (*FileACLState, error) {
	if strings.TrimSpace(path) == "" {
		return nil, &FileACLError{Kind: FileACLErrorInvalidInput, Message: "path must not be empty"}
	}
	script := psFileACLHeader + "\n" + strings.NewReplacer("@@PATH@@", psQuote(path)).Replace(psFileACLReadBody)
	resp, err := f.runScript(ctx, "read", script, "")
	if err != nil {
		if IsFileACLError(err, FileACLErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseFileACLPayload(resp.Data, path)
}

// Reset restores inheritance and strips the managed explicit ACEs. The target
// itself is never deleted, and a missing target is a silent success.
func (f *FileACLClientImpl) Reset(ctx context.Context, path string, managed []FileACLAccessRule) error {
	if strings.TrimSpace(path) == "" {
		return &FileACLError{Kind: FileACLErrorInvalidInput, Message: "path must not be empty"}
	}
	spec := FileACLInput{Path: path, Mode: FileACLModeAdditive, AccessRules: managed}
	for i := range spec.AccessRules {
		rule, err := normaliseFileACLRule(spec.AccessRules[i])
		if err != nil {
			return err
		}
		spec.AccessRules[i] = rule
	}
	payload, err := json.Marshal(spec)
	if err != nil {
		return &FileACLError{Kind: FileACLErrorInvalidInput, Message: "cannot encode ACL specification", Cause: err}
	}
	script := psFileACLHeader + "\n" + psFileACLResetBody
	_, err = f.runScript(ctx, "reset", script, string(payload))
	if err != nil && !IsFileACLError(err, FileACLErrorNotFound) {
		return err
	}
	return nil
}

// parseFileACLPayload converts the JSON data blob into a *FileACLState.
// Returns (nil, nil) when found=false.
func parseFileACLPayload(raw json.RawMessage, path string) (*FileACLState, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var payload fileACLDataPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &FileACLError{Kind: FileACLErrorUnknown, Message: "failed to parse ACL payload", Cause: err}
	}
	if !payload.Found {
		return nil, nil
	}
	rules, err := parseFileACLRules(payload.AccessRules)
	if err != nil {
		return nil, err
	}
	observed := payload.Path
	if observed == "" {
		observed = path
	}
	targetType := payload.TargetType
	if targetType != FileACLTargetFile && targetType != FileACLTargetDirectory {
		targetType = FileACLTargetFile
	}
	return &FileACLState{
		Path:               observed,
		TargetType:         targetType,
		Owner:              payload.Owner,
		OwnerSID:           payload.OwnerSID,
		InheritanceEnabled: payload.InheritanceEnabled,
		SDDL:               payload.SDDL,
		AccessRules:        rules,
	}, nil
}

// parseFileACLRules decodes the access_rules blob, tolerating the single-element
// object that ConvertTo-Json emits instead of a one-element array.
func parseFileACLRules(raw json.RawMessage) ([]FileACLAccessRule, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []FileACLAccessRule{}, nil
	}
	trimmed := strings.TrimSpace(string(raw))

	var decoded []FileACLAccessRule
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, &FileACLError{Kind: FileACLErrorUnknown, Message: "failed to parse access rules", Cause: err}
		}
	} else {
		var single FileACLAccessRule
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, &FileACLError{Kind: FileACLErrorUnknown, Message: "failed to parse access rule", Cause: err}
		}
		decoded = []FileACLAccessRule{single}
	}

	out := make([]FileACLAccessRule, 0, len(decoded))
	for _, rule := range decoded {
		// The mask is kept exactly as the host reports it: rewriting it would
		// corrupt FullControl (see FileACLRightSynchronize). Tolerance for the
		// Synchronize bit belongs in comparison, not in storage.
		rights, residual := FileACLRightsFromMask(rule.AccessMask)
		rule.Rights = rights
		if residual != 0 {
			// Bits no keyword covers: keep them in the mask (which is what drift
			// compares) rather than pretend the ACE is narrower than it is.
			rule.Rights = append(rule.Rights, fmt.Sprintf("0x%X", residual))
		}
		if rule.Type != FileACLTypeDeny {
			rule.Type = FileACLTypeAllow
		}
		if rule.Inheritance == "" {
			rule.Inheritance = FileACLInheritanceNone
		}
		if rule.Propagation == "" {
			rule.Propagation = FileACLPropagationNone
		}
		out = append(out, rule)
	}
	return out, nil
}
