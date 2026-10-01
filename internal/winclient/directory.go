// Package winclient: windows_directory CRUD implementation over SSH.
//
// Transport invariants:
//   - Every user-supplied path reaches a script only through psQuote.
//   - Scripts are sent via -EncodedCommand (UTF-16LE base64) by
//     Client.RunPowerShell.
//
// Security invariants:
//   - Every user-supplied string reaching a script goes through psQuote.
//   - Classify-DirectoryError reads the .NET exception type / HResult rather
//     than localized message text, so error classification is immune to the
//     locale of the target host (same pattern as file.go/Classify-FileError).
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Compile-time assertion: DirectoryClientImpl satisfies DirectoryClient.
var _ DirectoryClient = (*DirectoryClientImpl)(nil)

// DirectoryClientImpl is the PowerShell/SSH-backed DirectoryClient.
type DirectoryClientImpl struct {
	c *Client
}

// NewDirectoryClient constructs a DirectoryClientImpl wrapping the given SSH Client.
func NewDirectoryClient(c *Client) *DirectoryClientImpl {
	return &DirectoryClientImpl{c: c}
}

// psDirectoryHeader holds every PowerShell helper shared by the directory scripts.
const psDirectoryHeader = `
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

# Classify-DirectoryError maps a .NET exception to a DirectoryErrorKind. Win32
# codes are read from HResult rather than from message text so the mapping is
# immune to the locale of the target host.
function Classify-DirectoryError($Rec) {
  $ex = $Rec.Exception
  while ($null -ne $ex -and $ex -is [System.Management.Automation.MethodInvocationException] -and $null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  if ($ex -is [System.UnauthorizedAccessException])   { return 'permission_denied' }
  if ($ex -is [System.IO.DirectoryNotFoundException]) { return 'invalid_input' }
  if ($ex -is [System.IO.IOException]) {
    $code = 0
    try { $code = [int]($ex.HResult -band 0xFFFF) } catch { $code = 0 }
    switch ($code) {
      5   { return 'permission_denied' }  # ERROR_ACCESS_DENIED
      145 { return 'not_empty' }          # ERROR_DIR_NOT_EMPTY
      183 { return 'type_conflict' }      # ERROR_ALREADY_EXISTS (a file with that name)
    }
    return 'unknown'
  }
  return 'unknown'
}

function Get-DirAttrList($A) {
  $out = New-Object System.Collections.ArrayList
  if ($A -band [System.IO.FileAttributes]::Hidden)   { [void]$out.Add('hidden') }
  if ($A -band [System.IO.FileAttributes]::ReadOnly) { [void]$out.Add('readonly') }
  if ($A -band [System.IO.FileAttributes]::System)   { [void]$out.Add('system') }
  return ,([string[]]$out.ToArray())
}

function Set-DirAttrs([string]$P, [string[]]$Wanted) {
  $val = [System.IO.FileAttributes]::Directory
  foreach ($w in $Wanted) {
    switch ($w) {
      'hidden'   { $val = $val -bor [System.IO.FileAttributes]::Hidden }
      'readonly' { $val = $val -bor [System.IO.FileAttributes]::ReadOnly }
      'system'   { $val = $val -bor [System.IO.FileAttributes]::System }
    }
  }
  [System.IO.File]::SetAttributes($P, $val)
}

function Build-DirectoryData([string]$P) {
  $di = New-Object System.IO.DirectoryInfo $P
  $di.Refresh()
  $children = $di.GetFileSystemInfos()
  return [ordered]@{
    found            = $true
    exists_children  = ($children.Count -gt 0)
    item_count       = [int64]$children.Count
    last_write_time  = $di.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    attributes       = (Get-DirAttrList $di.Attributes)
  }
}
`

// psDirectoryCreateBody creates (or no-ops on an already-present, EC-9)
// directory and applies the requested attributes.
// Placeholders: @@PATH@@, @@CREATE_PARENTS@@, @@ATTRS@@
const psDirectoryCreateBody = `
function New-Directory([string]$P, [bool]$CreateParents, [string[]]$Wanted) {
  if (Test-Path -LiteralPath $P -PathType Leaf) {
    Emit-Err 'type_conflict' ("Path '" + $P + "' exists and is a file, not a directory.") @{ path = $P }
    return
  }
  if (-not (Test-Path -LiteralPath $P -PathType Container)) {
    $parent = Split-Path -Path $P -Parent
    if (-not $CreateParents -and $parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
      Emit-Err 'invalid_input' ("Parent directory '" + $parent + "' does not exist and create_parent_directories is false.") @{ path = $P; parent = $parent }
      return
    }
    try {
      New-Item -ItemType Directory -Path $P -Force:$CreateParents -ErrorAction Stop | Out-Null
    } catch {
      Emit-Err (Classify-DirectoryError $_) $_.Exception.Message @{ path = $P }
      return
    }
  }
  try {
    Set-DirAttrs $P $Wanted
  } catch {
    Emit-Err (Classify-DirectoryError $_) $_.Exception.Message @{ path = $P }
    return
  }
  Emit-OK (Build-DirectoryData $P)
}
`

// psDirectoryReadBody emits the directory data (or found:false when absent).
// Placeholders: @@PATH@@
const psDirectoryReadBody = `
function Read-Directory([string]$P) {
  if (Test-Path -LiteralPath $P -PathType Leaf) {
    Emit-Err 'type_conflict' ("Path '" + $P + "' is a file, not a directory.") @{ path = $P }
    return
  }
  if (-not (Test-Path -LiteralPath $P -PathType Container)) {
    Emit-OK @{ found = $false }
    return
  }
  Emit-OK (Build-DirectoryData $P)
}
`

// psDirectoryUpdateBody applies attributes to an existing directory.
// Placeholders: @@PATH@@, @@ATTRS@@
const psDirectoryUpdateBody = `
function Update-DirectoryAttrs([string]$P, [string[]]$Wanted) {
  if (Test-Path -LiteralPath $P -PathType Leaf) {
    Emit-Err 'type_conflict' ("Path '" + $P + "' is a file, not a directory.") @{ path = $P }
    return
  }
  if (-not (Test-Path -LiteralPath $P -PathType Container)) {
    Emit-Err 'not_found' ("Directory '" + $P + "' does not exist.") @{ path = $P }
    return
  }
  try {
    Set-DirAttrs $P $Wanted
  } catch {
    Emit-Err (Classify-DirectoryError $_) $_.Exception.Message @{ path = $P }
    return
  }
  Emit-OK (Build-DirectoryData $P)
}
`

// psDirectoryDeleteBody removes a directory, optionally recursively.
// Placeholders: @@PATH@@, @@RECURSIVE@@
const psDirectoryDeleteBody = `
function Remove-Directory([string]$P, [bool]$Recursive) {
  if (-not (Test-Path -LiteralPath $P -PathType Container)) {
    Emit-OK @{ deleted = $false }
    return
  }
  $di = New-Object System.IO.DirectoryInfo $P
  $hasChildren = ($di.GetFileSystemInfos().Count -gt 0)
  if ($hasChildren -and -not $Recursive) {
    Emit-Err 'not_empty' ("Directory '" + $P + "' is not empty; set recursive_delete=true to delete its content.") @{ path = $P }
    return
  }
  try {
    Remove-Item -LiteralPath $P -Force -Recurse:$Recursive -ErrorAction Stop
  } catch {
    Emit-Err (Classify-DirectoryError $_) $_.Exception.Message @{ path = $P }
    return
  }
  Emit-OK @{ deleted = $true }
}
`

// directoryPSResponse is the parsed JSON envelope for directory operations.
type directoryPSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// directoryDataPayload mirrors the JSON object returned by Build-DirectoryData.
type directoryDataPayload struct {
	Found          bool     `json:"found"`
	ExistsChildren bool     `json:"exists_children"`
	ItemCount      int64    `json:"item_count"`
	LastWriteTime  string   `json:"last_write_time"`
	Attributes     []string `json:"attributes"`
}

// runDirectoryPowerShell is the indirection used by DirectoryClientImpl. Tests
// can override it; production code must not.
var runDirectoryPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

// mapDirectoryKind translates the PS-side "kind" string to a typed DirectoryErrorKind.
func mapDirectoryKind(k string) DirectoryErrorKind {
	switch k {
	case string(DirectoryErrorNotFound),
		string(DirectoryErrorTypeConflict),
		string(DirectoryErrorPermission),
		string(DirectoryErrorNotEmpty),
		string(DirectoryErrorInvalidInput):
		return DirectoryErrorKind(k)
	default:
		return DirectoryErrorUnknown
	}
}

// runDirectoryEnvelope executes script (prepended with psDirectoryHeader) and
// parses the JSON envelope.
func (d *DirectoryClientImpl) runDirectoryEnvelope(ctx context.Context, op, path, script string) (*directoryPSResponse, error) {
	full := psDirectoryHeader + "\n" + script
	stdout, stderr, err := runDirectoryPowerShell(ctx, d.c, full)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, NewDirectoryError(DirectoryErrorUnknown,
				fmt.Sprintf("operation %q on directory %q timed out or was cancelled", op, path),
				ctxErr,
				map[string]string{"operation": op, "path": path, "host": d.c.cfg.Host})
		}
		return nil, NewDirectoryError(DirectoryErrorUnknown,
			fmt.Sprintf("SSH transport error during %q", op),
			err,
			map[string]string{
				"operation": op, "path": path, "host": d.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}

	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, NewDirectoryError(DirectoryErrorUnknown,
			fmt.Sprintf("no JSON envelope returned from %q", op), nil,
			map[string]string{
				"operation": op, "path": path, "host": d.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			})
	}
	var resp directoryPSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, NewDirectoryError(DirectoryErrorUnknown,
			fmt.Sprintf("invalid JSON envelope from %q", op), jerr,
			map[string]string{"operation": op, "path": path, "host": d.c.cfg.Host, "stdout": truncate(stdout, 2048)})
	}
	if !resp.OK {
		kind := mapDirectoryKind(resp.Kind)
		ctxMap := resp.Context
		if ctxMap == nil {
			ctxMap = map[string]string{}
		}
		ctxMap["operation"] = op
		ctxMap["path"] = path
		ctxMap["host"] = d.c.cfg.Host
		msg := resp.Message
		if kind == DirectoryErrorPermission {
			msg += " (sufficient NTFS permissions on the target directory are required.)"
		}
		return &resp, NewDirectoryError(kind, msg, nil, ctxMap)
	}
	return &resp, nil
}

func toDirectoryState(path string, d *directoryDataPayload) *DirectoryState {
	if d == nil {
		return nil
	}
	return &DirectoryState{
		Path:           path,
		ExistsChildren: d.ExistsChildren,
		ItemCount:      d.ItemCount,
		LastWriteTime:  d.LastWriteTime,
		Attributes:     d.Attributes,
	}
}

// Create implements DirectoryClient.Create.
//
// Idempotent when the directory already exists (EC-9): no already_exists
// error is raised, unlike windows_file. Refuses (type_conflict) when path is
// an existing file (EC-2), and (invalid_input) when a parent directory is
// missing and CreateParents is false (EC-3).
func (d *DirectoryClientImpl) Create(ctx context.Context, input DirectoryInput) (*DirectoryState, error) {
	if strings.TrimSpace(input.Path) == "" {
		return nil, NewDirectoryError(DirectoryErrorInvalidInput, "path is empty", nil, nil)
	}
	attrs, err := NormaliseDirectoryAttributes(input.Attributes)
	if err != nil {
		return nil, err
	}
	call := fmt.Sprintf("New-Directory -P %s -CreateParents:$%s -Wanted %s",
		psQuote(input.Path), psBool(input.CreateParents), psQuoteList(attrs))
	script := psDirectoryCreateBody + "\n" + call + "\n"
	resp, runErr := d.runDirectoryEnvelope(ctx, "create", input.Path, script)
	if runErr != nil {
		return nil, runErr
	}
	var payload directoryDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewDirectoryError(DirectoryErrorUnknown, "failed to parse create payload", jerr, map[string]string{"path": input.Path})
	}
	return toDirectoryState(input.Path, &payload), nil
}

// Read implements DirectoryClient.Read.
//
// Returns (nil, nil) when the directory does not exist (EC-1).
func (d *DirectoryClientImpl) Read(ctx context.Context, path string) (*DirectoryState, error) {
	if strings.TrimSpace(path) == "" {
		return nil, NewDirectoryError(DirectoryErrorInvalidInput, "path is empty", nil, nil)
	}
	script := psDirectoryReadBody + "\nRead-Directory -P " + psQuote(path) + "\n"
	resp, err := d.runDirectoryEnvelope(ctx, "read", path, script)
	if err != nil {
		return nil, err
	}
	var payload directoryDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewDirectoryError(DirectoryErrorUnknown, "failed to parse read payload", jerr, map[string]string{"path": path})
	}
	if !payload.Found {
		return nil, nil
	}
	return toDirectoryState(path, &payload), nil
}

// Update implements DirectoryClient.Update.
//
// Applies the given attributes to an already-present directory. Returns
// DirectoryErrorNotFound when the directory does not exist.
func (d *DirectoryClientImpl) Update(ctx context.Context, path string, attributes []string) (*DirectoryState, error) {
	if strings.TrimSpace(path) == "" {
		return nil, NewDirectoryError(DirectoryErrorInvalidInput, "path is empty", nil, nil)
	}
	attrs, err := NormaliseDirectoryAttributes(attributes)
	if err != nil {
		return nil, err
	}
	call := fmt.Sprintf("Update-DirectoryAttrs -P %s -Wanted %s", psQuote(path), psQuoteList(attrs))
	script := psDirectoryUpdateBody + "\n" + call + "\n"
	resp, runErr := d.runDirectoryEnvelope(ctx, "update", path, script)
	if runErr != nil {
		return nil, runErr
	}
	var payload directoryDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, NewDirectoryError(DirectoryErrorUnknown, "failed to parse update payload", jerr, map[string]string{"path": path})
	}
	return toDirectoryState(path, &payload), nil
}

// Delete implements DirectoryClient.Delete.
//
// Idempotent: a missing directory is a silent no-op (EC-5). Returns
// DirectoryErrorNotEmpty when the directory has content and recursive is
// false (EC-4).
func (d *DirectoryClientImpl) Delete(ctx context.Context, path string, recursive bool) error {
	if strings.TrimSpace(path) == "" {
		return NewDirectoryError(DirectoryErrorInvalidInput, "path is empty", nil, nil)
	}
	call := fmt.Sprintf("Remove-Directory -P %s -Recursive:$%s", psQuote(path), psBool(recursive))
	script := psDirectoryDeleteBody + "\n" + call + "\n"
	_, err := d.runDirectoryEnvelope(ctx, "delete", path, script)
	return err
}
