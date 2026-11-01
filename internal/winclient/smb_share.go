// Package winclient: windows_smb_share CRUD implementation over SSH.
//
// Transport invariants:
//   - Every user-supplied value reaches a script only through psQuote /
//     psQuoteList (single-quoted PowerShell literals). No raw string
//     concatenation of user input into scripts.
//   - Scripts are sent via -EncodedCommand (UTF-16LE base64) by
//     Client.RunPowerShell.
//
// Security invariants:
//   - Error classification prefers .NET exception types, CategoryInfo
//     categories and FullyQualifiedErrorId over localized message text, so
//     the mapping survives a non-English target host (same pattern as
//     file.go/Classify-FileError). Message substrings are only the last
//     resort, and only for tokens that are not localized (cmdlet and
//     service names such as LanmanServer).
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: SmbShareClientImpl satisfies SmbShareClient.
var _ SmbShareClient = (*SmbShareClientImpl)(nil)

// SmbShareClientImpl is the PowerShell/SSH-backed SmbShareClient.
type SmbShareClientImpl struct {
	c *Client
}

// NewSmbShareClient constructs a SmbShareClientImpl wrapping the given SSH Client.
func NewSmbShareClient(c *Client) *SmbShareClientImpl {
	return &SmbShareClientImpl{c: c}
}

// runSmbSharePowerShell is the indirection used by SmbShareClientImpl. Tests
// can override it; production code must not.
var runSmbSharePowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// psSmbShareHeader holds every PowerShell helper shared by the SMB share scripts.
const psSmbShareHeader = `
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

# Classify-SmbShare maps a caught error record to a SmbShareErrorKind. The
# Smb* cmdlets are CIM-based, so classification prefers the .NET exception
# TYPE, the CategoryInfo category and the FullyQualifiedErrorId over
# localized message text. The category/FQID checks run regardless of the
# exact .NET exception type: Get-SmbShare throws CimException on Windows
# PowerShell 5.1 but CimJobException
# (Microsoft.PowerShell.Cmdletization.Cim.CimJobException) on PowerShell 7+,
# so gating on one type misses the missing-share record there. The Server
# 2025 / PS7 missing-share record is Category ObjectNotFound, FQID
# CmdletizationQuery_NotFound_Name,Get-SmbShare, message "No MSFT_SMBShare
# objects found with property 'Name' equal to ...". Message
# substrings are only the last resort, and only for tokens that are not
# localized (cmdlet and service names such as LanmanServer, and the
# MSFT_SMBShare class name).
function Classify-SmbShare($Rec) {
  $ex = $Rec.Exception
  while ($null -ne $ex -and $ex -is [System.Management.Automation.MethodInvocationException] -and $null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  if ($ex -is [System.Security.Principal.IdentityNotMappedException]) { return 'principal_not_found' }
  if ($ex -is [System.UnauthorizedAccessException])   { return 'permission_denied' }
  if ($ex -is [System.IO.DirectoryNotFoundException]) { return 'path_not_found' }
  if ($ex -is [System.ArgumentException])             { return 'invalid_name' }
  if ($ex -is [System.IO.IOException]) {
    $code = 0
    try { $code = [int]($ex.HResult -band 0xFFFF) } catch { $code = 0 }
    switch ($code) {
      3    { return 'path_not_found' }               # ERROR_PATH_NOT_FOUND
      5    { return 'permission_denied' }            # ERROR_ACCESS_DENIED
      53   { return 'path_not_found' }               # ERROR_BAD_NETPATH
      1056 { return 'server_service_unavailable' }   # ERROR_SERVICE_ALREADY_RUNNING (LanmanServer state)
      1058 { return 'server_service_unavailable' }   # ERROR_SERVICE_DISABLED
      1062 { return 'server_service_unavailable' }   # ERROR_SERVICE_NOT_ACTIVE
    }
  }
  $cmsg = [string]$ex.Message
  if ($cmsg -match 'LanmanServer') { return 'server_service_unavailable' }
  $cat = [string]$Rec.CategoryInfo.Category
  if ($cat -match 'ObjectNotFound')     { return 'not_found' }
  if ($cat -match 'ResourceExists')     { return 'already_exists' }
  if ($cat -match 'PermissionDenied|UnauthorizedAccess') { return 'permission_denied' }
  if ($cat -match 'InvalidArgument|InvalidData') { return 'invalid_name' }
  $fid = [string]$Rec.FullyQualifiedErrorId
  if ($fid -match 'AlreadyExists|ResourceExists') { return 'already_exists' }
  if ($fid -match 'NotFound') { return 'not_found' }
  $msg = [string]$Rec.Exception.Message
  if ($msg -match 'LanmanServer') { return 'server_service_unavailable' }
  if ($msg -match 'already exists') { return 'already_exists' }
  if ($msg -match 'No MSFT_SMBShare objects found') { return 'not_found' }
  if ($msg -match 'cannot find|was not found|no such share|does not exist') { return 'not_found' }
  if ($msg -match 'cannot resolve|IdentityNotMapped|not a valid (trustee|SID)') { return 'principal_not_found' }
  if ($msg -match 'Access is denied') { return 'permission_denied' }
  return 'unknown'
}

# Resolve-SmbShareSID accepts a SID, a qualified name or a bare local name
# and returns the canonical SID string. A raw SID is NOT resolved through the
# account database: an orphaned SID left by a deleted account must stay
# usable. Failures throw IdentityNotMappedException so the caller classifies
# them as principal_not_found.
function Resolve-SmbShareSID([string]$Id) {
  if ($Id -match '^[Ss]-1-') {
    try {
      return ([string](New-Object System.Security.Principal.SecurityIdentifier($Id)).Value)
    } catch {
      throw (New-Object System.Security.Principal.IdentityNotMappedException(('not a valid SID: ' + $Id)))
    }
  }
  try {
    $acct = New-Object System.Security.Principal.NTAccount($Id)
    return ([string]($acct.Translate([System.Security.Principal.SecurityIdentifier])).Value)
  } catch {
    throw (New-Object System.Security.Principal.IdentityNotMappedException(('cannot resolve identity: ' + $Id)))
  }
}

# Get-SmbShareData renders one share plus its access list as the JSON
# payload. Every trustee carries the display name and a best-effort SID
# (empty when the account cannot be resolved on the host); SID comparison is
# the provider layer's job, so a best-effort value here never fails the read.
function Get-SmbShareData([string]$Name) {
  $s = Get-SmbShare -Name $Name -ErrorAction Stop
  $full   = New-Object System.Collections.ArrayList
  $change = New-Object System.Collections.ArrayList
  $read   = New-Object System.Collections.ArrayList
  $no     = New-Object System.Collections.ArrayList
  foreach ($a in @(Get-SmbShareAccess -Name $Name -ErrorAction Stop)) {
    $acct = [string]$a.AccountName
    $sid = ''
    try { $sid = Resolve-SmbShareSID $acct } catch { $sid = '' }
    if ([string]::IsNullOrEmpty($sid) -and $acct -match '^[Ss]-1-') { $sid = $acct }
    $entry = [ordered]@{ name = $acct; sid = $sid }
    $level = [string]$a.AccessRight
    if ([string]$a.AccessControlType -eq 'Deny' -or $level -eq 'No') {
      [void]$no.Add($entry)
    } elseif ($level -eq 'Full') {
      [void]$full.Add($entry)
    } elseif ($level -eq 'Change') {
      [void]$change.Add($entry)
    } elseif ($level -eq 'Read') {
      [void]$read.Add($entry)
    }
    # Custom-granularity Allow entries match no Terraform set and are
    # deliberately dropped: when access is managed they are revoked as stale,
    # which is what the authoritative contract promises.
  }
  return [ordered]@{
    found                   = $true
    name                    = [string]$s.Name
    path                    = [string]$s.Path
    description             = [string]$s.Description
    folder_enumeration_mode = [string]$s.FolderEnumerationMode
    caching_mode            = [string]$s.CachingMode
    concurrent_user_limit   = [int64]$s.ConcurrentUserLimit
    encrypt_data            = [bool]$s.EncryptData
    special                 = [bool]$s.Special
    full_access             = ([object[]]$full.ToArray())
    change_access           = ([object[]]$change.ToArray())
    read_access             = ([object[]]$read.ToArray())
    no_access               = ([object[]]$no.ToArray())
  }
}

# Sync-SmbShareAccess converges the share access list on exactly the desired
# trustees. Ordering is load-bearing:
#   Phase 1 grants every desired trustee first (a level change is
#   revoke-then-grant, because Revoke-SmbShareAccess strips every ACE of the
#   account), so the share never passes through a state with no access.
#   Phase 2 revokes every observed trustee that is not desired, including the
#   Everyone:Read entry New-SmbShare creates by default.
function Sync-SmbShareAccess([string]$Name, [string[]]$Full, [string[]]$Change, [string[]]$Read, [string[]]$No) {
  $desired = @{}
  foreach ($p in @($Full)) {
    $sid = Resolve-SmbShareSID $p
    if ($desired.ContainsKey($sid)) { throw ('duplicate trustee in desired access list: ' + $p) }
    $desired[$sid] = @{ level = 'Full'; name = $p }
  }
  foreach ($p in @($Change)) {
    $sid = Resolve-SmbShareSID $p
    if ($desired.ContainsKey($sid)) { throw ('duplicate trustee in desired access list: ' + $p) }
    $desired[$sid] = @{ level = 'Change'; name = $p }
  }
  foreach ($p in @($Read)) {
    $sid = Resolve-SmbShareSID $p
    if ($desired.ContainsKey($sid)) { throw ('duplicate trustee in desired access list: ' + $p) }
    $desired[$sid] = @{ level = 'Read'; name = $p }
  }
  foreach ($p in @($No)) {
    $sid = Resolve-SmbShareSID $p
    if ($desired.ContainsKey($sid)) { throw ('duplicate trustee in desired access list: ' + $p) }
    $desired[$sid] = @{ level = 'No'; name = $p }
  }

  $observed = @{}
  foreach ($a in @(Get-SmbShareAccess -Name $Name -ErrorAction Stop)) {
    $acct = [string]$a.AccountName
    $sid = ''
    try { $sid = Resolve-SmbShareSID $acct } catch { $sid = '' }
    if ([string]::IsNullOrEmpty($sid)) { $sid = 'NAME:' + $acct }
    $level = [string]$a.AccessRight
    if ([string]$a.AccessControlType -eq 'Deny' -or $level -eq 'No') { $level = 'No' }
    elseif ($level -ne 'Full' -and $level -ne 'Change' -and $level -ne 'Read') { $level = 'Custom' }
    $observed[$sid] = @{ level = $level; name = $acct }
  }

  # Phase 1: grant-new-first.
  foreach ($sid in @($desired.Keys)) {
    $want = $desired[$sid]
    if ($observed.ContainsKey($sid) -and $observed[$sid].level -eq $want.level) { continue }
    if ($observed.ContainsKey($sid)) {
      Revoke-SmbShareAccess -Name $Name -AccountName $observed[$sid].name -Force -ErrorAction Stop
    }
    if ($want.level -eq 'No') {
      Block-SmbShareAccess -Name $Name -AccountName $want.name -Force -ErrorAction Stop
    } else {
      Grant-SmbShareAccess -Name $Name -AccountName $want.name -AccessRight $want.level -Force -ErrorAction Stop
    }
  }

  # Phase 2: revoke-stale.
  foreach ($sid in @($observed.Keys)) {
    if ($desired.ContainsKey($sid)) { continue }
    Revoke-SmbShareAccess -Name $Name -AccountName $observed[$sid].name -Force -ErrorAction Stop
  }
}
`

// psSmbShareCreateBody pre-flights with Get-SmbShare (AlreadyExists carries
// an import hint), refuses a missing share path, creates the share, then
// converges the access list when it is managed.
// Placeholders: @@NAME@@, @@PATH@@, @@DESCRIPTION@@,
// @@FOLDER_ENUMERATION_MODE@@, @@CACHING_MODE@@, @@CONCURRENT_USER_LIMIT@@,
// @@ENCRYPT_DATA@@, @@FULL@@, @@CHANGE@@, @@READ@@, @@NO@@, @@MANAGE_ACCESS@@.
const psSmbShareCreateBody = `
& {
  $Name = @@NAME@@
  try {
    try {
      $null = Get-SmbShare -Name $Name -ErrorAction Stop
      Emit-Err 'already_exists' ('SMB share ' + $Name + ' already exists. Import it with: terraform import windows_smb_share.<label> ' + $Name) @{ name = $Name }
      return
    } catch {
      if ((Classify-SmbShare $_) -ne 'not_found') {
        Emit-Err (Classify-SmbShare $_) $_.Exception.Message @{ name = $Name; step = 'preflight' }
        return
      }
    }
    $Path = @@PATH@@
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
      Emit-Err 'path_not_found' ('share path ' + $Path + ' does not exist on the target host or is not a directory') @{ name = $Name; path = $Path }
      return
    }
    New-SmbShare -Name $Name -Path $Path -Description @@DESCRIPTION@@ -FolderEnumerationMode @@FOLDER_ENUMERATION_MODE@@ -CachingMode @@CACHING_MODE@@ -ConcurrentUserLimit @@CONCURRENT_USER_LIMIT@@ -EncryptData:$@@ENCRYPT_DATA@@ -ErrorAction Stop | Out-Null
    if ($@@MANAGE_ACCESS@@) {
      Sync-SmbShareAccess -Name $Name -Full @@FULL@@ -Change @@CHANGE@@ -Read @@READ@@ -No @@NO@@
    }
    Emit-OK (Get-SmbShareData $Name)
  } catch {
    Emit-Err (Classify-SmbShare $_) $_.Exception.Message @{ name = $Name }
  }
}
`

// psSmbShareReadBody emits the share data, or found:false when the share is
// absent. Placeholder: @@NAME@@.
const psSmbShareReadBody = `
& {
  $Name = @@NAME@@
  try {
    Emit-OK (Get-SmbShareData $Name)
  } catch {
    if ((Classify-SmbShare $_) -eq 'not_found') {
      Emit-OK @{ found = $false }
      return
    }
    Emit-Err (Classify-SmbShare $_) $_.Exception.Message @{ name = $Name }
  }
}
`

// psSmbShareUpdateBody applies the mutable share properties with Set-SmbShare
// -Force, then converges the access list when it is managed.
// Placeholders: same as the create body except @@PATH@@ (path is ForceNew).
const psSmbShareUpdateBody = `
& {
  $Name = @@NAME@@
  try {
    $null = Get-SmbShare -Name $Name -ErrorAction Stop
    Set-SmbShare -Name $Name -Description @@DESCRIPTION@@ -FolderEnumerationMode @@FOLDER_ENUMERATION_MODE@@ -CachingMode @@CACHING_MODE@@ -ConcurrentUserLimit @@CONCURRENT_USER_LIMIT@@ -EncryptData:$@@ENCRYPT_DATA@@ -Force -ErrorAction Stop
    if ($@@MANAGE_ACCESS@@) {
      Sync-SmbShareAccess -Name $Name -Full @@FULL@@ -Change @@CHANGE@@ -Read @@READ@@ -No @@NO@@
    }
    Emit-OK (Get-SmbShareData $Name)
  } catch {
    Emit-Err (Classify-SmbShare $_) $_.Exception.Message @{ name = $Name }
  }
}
`

// psSmbShareDeleteBody removes the share. A missing share is a silent
// success (idempotent delete). Placeholder: @@NAME@@.
const psSmbShareDeleteBody = `
& {
  $Name = @@NAME@@
  try {
    try {
      $null = Get-SmbShare -Name $Name -ErrorAction Stop
    } catch {
      if ((Classify-SmbShare $_) -eq 'not_found') {
        Emit-OK @{ deleted = $false }
        return
      }
      Emit-Err (Classify-SmbShare $_) $_.Exception.Message @{ name = $Name; step = 'lookup' }
      return
    }
    Remove-SmbShare -Name $Name -Force -ErrorAction Stop
    Emit-OK @{ deleted = $true }
  } catch {
    Emit-Err (Classify-SmbShare $_) $_.Exception.Message @{ name = $Name }
  }
}
`

// smbSharePSResponse is the parsed JSON envelope for SMB share operations. It
// aliases the shared Envelope type so every resource parses the same shape
// through runEnvelope (#198).
type smbSharePSResponse = Envelope

// smbShareTrusteePayload mirrors one JSON trustee object.
type smbShareTrusteePayload struct {
	Name string `json:"name"`
	SID  string `json:"sid"`
}

// smbShareDataPayload mirrors the JSON object returned by Get-SmbShareData.
// Access lists are json.RawMessage because ConvertTo-Json serialises a
// single-element array as a bare object.
type smbShareDataPayload struct {
	Found                 bool            `json:"found"`
	Name                  string          `json:"name"`
	Path                  string          `json:"path"`
	Description           string          `json:"description"`
	FolderEnumerationMode string          `json:"folder_enumeration_mode"`
	CachingMode           string          `json:"caching_mode"`
	ConcurrentUserLimit   int64           `json:"concurrent_user_limit"`
	EncryptData           bool            `json:"encrypt_data"`
	Special               bool            `json:"special"`
	FullAccess            json.RawMessage `json:"full_access"`
	ChangeAccess          json.RawMessage `json:"change_access"`
	ReadAccess            json.RawMessage `json:"read_access"`
	NoAccess              json.RawMessage `json:"no_access"`
}

// mapSmbShareKind translates the PS-side "kind" string to a typed kind.
func mapSmbShareKind(k string) SmbShareErrorKind {
	switch k {
	case string(SmbShareErrorNotFound),
		string(SmbShareErrorAlreadyExists),
		string(SmbShareErrorPathNotFound),
		string(SmbShareErrorAccessDenied),
		string(SmbShareErrorInvalidName),
		string(SmbShareErrorPrincipalNotFound),
		string(SmbShareErrorServerServiceUnavailable):
		return SmbShareErrorKind(k)
	default:
		return SmbShareErrorUnknown
	}
}

// runSmbShareEnvelope executes script (prepended with psSmbShareHeader) and
// parses the JSON envelope through the shared runEnvelope helper (#198).
func (s *SmbShareClientImpl) runSmbShareEnvelope(ctx context.Context, op, name, script string) (*smbSharePSResponse, error) {
	baseContext := map[string]string{
		"name": name,
		"host": s.c.cfg.Host,
	}
	resp, eerr := runEnvelope(ctx,
		func(ctx context.Context, full, stdin string) (string, string, error) {
			return runSmbSharePowerShell(ctx, s.c, full)
		},
		op, psSmbShareHeader+"\n"+script, "", baseContext)
	if eerr == nil {
		return resp, nil
	}
	if eerr.Stage == EnvelopeStageTimeout {
		eerr.Message = fmt.Sprintf("operation %q on SMB share %q timed out or was cancelled", op, name)
	}
	if eerr.Stage != EnvelopeStageRemote {
		return nil, NewSmbShareError(SmbShareErrorUnknown, eerr.Message, eerr.Cause, eerr.Context)
	}
	return resp, NewSmbShareError(mapSmbShareKind(eerr.RemoteKind), eerr.Message, nil, eerr.Context)
}

// buildSmbShareScript interpolates the share settings into a create/update
// body. Every user-supplied value goes through psQuote/psQuoteList.
func buildSmbShareScript(body, name, path string, s SmbShareSettings) string {
	return strings.NewReplacer(
		"@@NAME@@", psQuote(name),
		"@@PATH@@", psQuote(path),
		"@@DESCRIPTION@@", psQuote(s.Description),
		"@@FOLDER_ENUMERATION_MODE@@", psQuote(s.FolderEnumerationMode),
		"@@CACHING_MODE@@", psQuote(s.CachingMode),
		"@@CONCURRENT_USER_LIMIT@@", fmt.Sprintf("%d", s.ConcurrentUserLimit),
		"@@ENCRYPT_DATA@@", psBool(s.EncryptData),
		"@@FULL@@", psQuoteList(s.FullAccess),
		"@@CHANGE@@", psQuoteList(s.ChangeAccess),
		"@@READ@@", psQuoteList(s.ReadAccess),
		"@@NO@@", psQuoteList(s.NoAccess),
		"@@MANAGE_ACCESS@@", psBool(s.ManageAccess),
	).Replace(body)
}

// Create implements SmbShareClient.Create.
//
// Idempotency is explicit rather than adoptive: a pre-existing share is
// rejected with SmbShareErrorAlreadyExists carrying an import hint, unlike
// windows_directory which adopts a pre-existing directory.
func (s *SmbShareClientImpl) Create(ctx context.Context, input SmbShareInput) (*SmbShareInfo, error) {
	if err := ValidateSmbShareName(input.Name); err != nil {
		return nil, err
	}
	normPath, err := NormalizeSmbSharePath(input.Path)
	if err != nil {
		return nil, err
	}
	input.Path = normPath
	if err := ValidateSmbShareSettings(&input.SmbShareSettings); err != nil {
		return nil, err
	}
	script := buildSmbShareScript(psSmbShareCreateBody, input.Name, input.Path, input.SmbShareSettings)
	resp, runErr := s.runSmbShareEnvelope(ctx, "create", input.Name, script)
	if runErr != nil {
		return nil, runErr
	}
	st, perr := parseSmbSharePayload(resp.Data, input.Name)
	if perr != nil {
		return nil, perr
	}
	if st == nil {
		return nil, NewSmbShareError(SmbShareErrorUnknown, "create reported no share", nil, map[string]string{"name": input.Name})
	}
	return st, nil
}

// Read implements SmbShareClient.Read.
//
// Returns (nil, nil) when the share does not exist.
func (s *SmbShareClientImpl) Read(ctx context.Context, name string) (*SmbShareInfo, error) {
	if err := ValidateSmbShareName(name); err != nil {
		return nil, err
	}
	script := strings.NewReplacer("@@NAME@@", psQuote(name)).Replace(psSmbShareReadBody)
	resp, err := s.runSmbShareEnvelope(ctx, "read", name, script)
	if err != nil {
		return nil, err
	}
	return parseSmbSharePayload(resp.Data, name)
}

// Update implements SmbShareClient.Update.
//
// Applies the mutable share properties with Set-SmbShare -Force and
// converges the access list when it is managed. Returns
// SmbShareErrorNotFound when the share does not exist.
func (s *SmbShareClientImpl) Update(ctx context.Context, input SmbShareUpdateInput) (*SmbShareInfo, error) {
	if err := ValidateSmbShareName(input.Name); err != nil {
		return nil, err
	}
	if err := ValidateSmbShareSettings(&input.SmbShareSettings); err != nil {
		return nil, err
	}
	script := buildSmbShareScript(psSmbShareUpdateBody, input.Name, "", input.SmbShareSettings)
	resp, runErr := s.runSmbShareEnvelope(ctx, "update", input.Name, script)
	if runErr != nil {
		return nil, runErr
	}
	st, perr := parseSmbSharePayload(resp.Data, input.Name)
	if perr != nil {
		return nil, perr
	}
	if st == nil {
		return nil, NewSmbShareError(SmbShareErrorNotFound, fmt.Sprintf("SMB share %q does not exist", input.Name), nil, map[string]string{"name": input.Name})
	}
	return st, nil
}

// Delete implements SmbShareClient.Delete.
//
// Idempotent: a missing share is a silent no-op.
func (s *SmbShareClientImpl) Delete(ctx context.Context, name string) error {
	if err := ValidateSmbShareName(name); err != nil {
		return err
	}
	script := strings.NewReplacer("@@NAME@@", psQuote(name)).Replace(psSmbShareDeleteBody)
	_, err := s.runSmbShareEnvelope(ctx, "delete", name, script)
	return err
}

// parseSmbSharePayload converts the JSON data blob into a *SmbShareInfo.
// Returns (nil, nil) when found=false.
func parseSmbSharePayload(raw json.RawMessage, name string) (*SmbShareInfo, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var payload smbShareDataPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &SmbShareError{Kind: SmbShareErrorUnknown, Message: "failed to parse SMB share payload", Cause: err}
	}
	if !payload.Found {
		return nil, nil
	}
	full, err := parseSmbShareTrustees(payload.FullAccess)
	if err != nil {
		return nil, err
	}
	change, err := parseSmbShareTrustees(payload.ChangeAccess)
	if err != nil {
		return nil, err
	}
	read, err := parseSmbShareTrustees(payload.ReadAccess)
	if err != nil {
		return nil, err
	}
	no, err := parseSmbShareTrustees(payload.NoAccess)
	if err != nil {
		return nil, err
	}
	observed := payload.Name
	if observed == "" {
		observed = name
	}
	return &SmbShareInfo{
		Name:                  observed,
		Path:                  payload.Path,
		Description:           payload.Description,
		FolderEnumerationMode: payload.FolderEnumerationMode,
		CachingMode:           payload.CachingMode,
		ConcurrentUserLimit:   payload.ConcurrentUserLimit,
		EncryptData:           payload.EncryptData,
		Special:               payload.Special,
		FullAccess:            full,
		ChangeAccess:          change,
		ReadAccess:            read,
		NoAccess:              no,
	}, nil
}

// parseSmbShareTrustees decodes one access list blob, tolerating the
// single-element object that ConvertTo-Json emits instead of a one-element
// array, as well as null and missing values.
func parseSmbShareTrustees(raw json.RawMessage) ([]SmbShareTrustee, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []SmbShareTrustee{}, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	var decoded []smbShareTrusteePayload
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, &SmbShareError{Kind: SmbShareErrorUnknown, Message: "failed to parse share access list", Cause: err}
		}
	} else {
		var single smbShareTrusteePayload
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, &SmbShareError{Kind: SmbShareErrorUnknown, Message: "failed to parse share access entry", Cause: err}
		}
		decoded = []smbShareTrusteePayload{single}
	}
	out := make([]SmbShareTrustee, 0, len(decoded))
	for _, t := range decoded {
		out = append(out, SmbShareTrustee(t))
	}
	return out, nil
}
