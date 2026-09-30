// Package winclient: windows_directory CRUD implementation over SSH + PowerShell.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

var _ DirectoryClient = (*DirectoryClientImpl)(nil)

type DirectoryClientImpl struct{ c *Client }

func NewDirectoryClient(c *Client) *DirectoryClientImpl { return &DirectoryClientImpl{c: c} }

const psDirectoryHeader = `
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
function Emit-OK([object]$Data) {
  [Console]::Out.WriteLine(([ordered]@{ ok=$true; data=$Data } | ConvertTo-Json -Depth 12 -Compress))
}
function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx) {
  if ($null -eq $Ctx) { $Ctx = @{} }
  [Console]::Out.WriteLine(([ordered]@{ ok=$false; kind=$Kind; message=$Message; context=$Ctx } | ConvertTo-Json -Depth 8 -Compress))
}
function Classify-DirectoryError($Rec) {
  $ex = $Rec.Exception
  while ($null -ne $ex -and $ex.InnerException -and $ex -is [System.Management.Automation.MethodInvocationException]) { $ex = $ex.InnerException }
  if ($ex -is [System.UnauthorizedAccessException]) { return 'permission_denied' }
  if ($ex -is [System.IO.DirectoryNotFoundException]) { return 'path_not_found' }
  if ($ex -is [System.IO.PathTooLongException] -or $ex -is [System.ArgumentException]) { return 'invalid_input' }
  if ($ex -is [System.IO.IOException]) {
    $code = 0
    try { $code = [int]($ex.HResult -band 0xFFFF) } catch { $code = 0 }
    switch ($code) {
      2 { return 'not_found' }
      3 { return 'path_not_found' }
      5 { return 'permission_denied' }
      145 { return 'directory_not_empty' }
    }
    return 'unknown'
  }
  return 'unknown'
}
function Get-DirectoryAttrList($A) {
  $out = New-Object System.Collections.ArrayList
  if ($A -band [System.IO.FileAttributes]::Archive) { [void]$out.Add('archive') }
  if ($A -band [System.IO.FileAttributes]::Hidden) { [void]$out.Add('hidden') }
  if ($A -band [System.IO.FileAttributes]::ReadOnly) { [void]$out.Add('readonly') }
  if ($A -band [System.IO.FileAttributes]::System) { [void]$out.Add('system') }
  if ($A -band [System.IO.FileAttributes]::Temporary) { [void]$out.Add('temporary') }
  return ,([string[]]$out.ToArray())
}
function Set-DirectoryAttrs([string]$P, [string[]]$Wanted) {
  $val = [System.IO.FileAttributes]::Normal
  foreach ($w in $Wanted) {
    switch ($w) {
      'archive' { $val = $val -bor [System.IO.FileAttributes]::Archive }
      'hidden' { $val = $val -bor [System.IO.FileAttributes]::Hidden }
      'readonly' { $val = $val -bor [System.IO.FileAttributes]::ReadOnly }
      'system' { $val = $val -bor [System.IO.FileAttributes]::System }
      'temporary' { $val = $val -bor [System.IO.FileAttributes]::Temporary }
    }
  }
  [System.IO.File]::SetAttributes($P, $val)
}
function Build-DirectoryData([string]$P) {
  $di = New-Object System.IO.DirectoryInfo $P
  $di.Refresh()
  return [ordered]@{
    found=$true
    last_write_time=$di.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    attributes=(Get-DirectoryAttrList $di.Attributes)
  }
}
`

const psDirectorySetBody = `
& {
  $target = @@PATH@@
  $wanted = @@ATTRS@@
  try {
    if ([System.IO.File]::Exists($target)) {
      Emit-Err 'type_conflict' ('path exists and is a file: ' + $target) @{ path=$target }
      return
    }
    $created = $false
    if (-not [System.IO.Directory]::Exists($target)) {
      $parent = [System.IO.Path]::GetDirectoryName($target)
      if (-not @@CREATE_PARENTS@@ -and $parent -and -not [System.IO.Directory]::Exists($parent)) {
        Emit-Err 'path_not_found' ('parent directory does not exist: ' + $parent) @{ path=$target; parent=$parent }
        return
      }
      [System.IO.Directory]::CreateDirectory($target) | Out-Null
      $created = $true
    }
    Set-DirectoryAttrs $target $wanted
    Emit-OK (Build-DirectoryData $target)
  } catch {
    Emit-Err (Classify-DirectoryError $_) $_.Exception.Message @{ path=$target }
  }
}
`

const psDirectoryReadBody = `
& {
  $target = @@PATH@@
  try {
    if ([System.IO.File]::Exists($target)) {
      Emit-Err 'type_conflict' ('path exists and is a file: ' + $target) @{ path=$target }
      return
    }
    if (-not [System.IO.Directory]::Exists($target)) { Emit-OK @{ found=$false }; return }
    Emit-OK (Build-DirectoryData $target)
  } catch {
    Emit-Err (Classify-DirectoryError $_) $_.Exception.Message @{ path=$target }
  }
}
`

const psDirectoryDeleteBody = `
& {
  $target = @@PATH@@
  try {
    if ([System.IO.File]::Exists($target)) {
      Emit-Err 'type_conflict' ('path exists and is a file: ' + $target) @{ path=$target }
      return
    }
    if (-not [System.IO.Directory]::Exists($target)) { Emit-OK @{ deleted=$false }; return }
    if (@@RECURSIVE@@) {
      Remove-Item -LiteralPath $target -Recurse -Force
    } else {
      $child = Get-ChildItem -LiteralPath $target -Force | Select-Object -First 1
      if ($null -ne $child) {
        Emit-Err 'directory_not_empty' ('directory is not empty: ' + $target) @{ path=$target }
        return
      }
      Remove-Item -LiteralPath $target -Force
    }
    Emit-OK @{ deleted=$true }
  } catch {
    Emit-Err (Classify-DirectoryError $_) $_.Exception.Message @{ path=$target }
  }
}
`

type directoryPSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}
type directoryData struct {
	Found         bool     `json:"found"`
	Deleted       bool     `json:"deleted"`
	LastWriteTime string   `json:"last_write_time"`
	Attributes    []string `json:"attributes"`
}

var runDirectoryPowerShell = func(ctx context.Context, c *Client, script string) (string, string, error) {
	return c.RunPowerShell(ctx, script)
}

func (d *DirectoryClientImpl) run(ctx context.Context, op, script string) (*directoryPSResponse, error) {
	stdout, stderr, err := runDirectoryPowerShell(ctx, d.c, script)
	if err != nil {
		if ctx.Err() != nil {
			return nil, &DirectoryError{Kind: DirectoryErrorUnknown, Message: fmt.Sprintf("operation %q timed out or was cancelled", op), Cause: ctx.Err()}
		}
		return nil, &DirectoryError{Kind: DirectoryErrorUnknown, Message: fmt.Sprintf("SSH transport error during %q", op), Cause: err, Context: map[string]string{"stderr": truncate(stderr, 2048), "stdout": truncate(stdout, 2048)}}
	}
	line := extractLastJSONLine(stdout)
	if line == "" {
		return nil, &DirectoryError{Kind: DirectoryErrorUnknown, Message: fmt.Sprintf("no JSON envelope returned from %q", op), Context: map[string]string{"stderr": truncate(stderr, 2048), "stdout": truncate(stdout, 2048)}}
	}
	var response directoryPSResponse
	if err := json.Unmarshal([]byte(line), &response); err != nil {
		return nil, &DirectoryError{Kind: DirectoryErrorUnknown, Message: fmt.Sprintf("invalid JSON envelope from %q", op), Cause: err}
	}
	if !response.OK {
		kind := DirectoryErrorKind(response.Kind)
		switch kind {
		case DirectoryErrorTypeConflict, DirectoryErrorPathNotFound, DirectoryErrorPermission, DirectoryErrorNotEmpty, DirectoryErrorInvalidInput, DirectoryErrorNotFound:
		default:
			kind = DirectoryErrorUnknown
		}
		return nil, &DirectoryError{Kind: kind, Message: response.Message, Context: response.Context}
	}
	return &response, nil
}

func directoryAttrsLiteral(attrs []string) string {
	parts := make([]string, 0, len(attrs))
	for _, a := range attrs {
		parts = append(parts, psQuote(a))
	}
	return "@(" + strings.Join(parts, ",") + ")"
}

func (d *DirectoryClientImpl) Set(ctx context.Context, input DirectoryInput) (*DirectoryState, error) {
	script := psDirectoryHeader + strings.NewReplacer(
		"@@PATH@@", psQuote(input.Path),
		"@@ATTRS@@", directoryAttrsLiteral(input.Attributes),
		"@@CREATE_PARENTS@@", "$"+psBool(input.CreateParents),
	).Replace(psDirectorySetBody)
	response, err := d.run(ctx, "set", script)
	if err != nil {
		return nil, err
	}
	var data directoryData
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return nil, &DirectoryError{Kind: DirectoryErrorUnknown, Message: "failed to parse set response data", Cause: err}
	}
	return &DirectoryState{Path: input.Path, LastWriteTime: data.LastWriteTime, Attributes: data.Attributes}, nil
}

func (d *DirectoryClientImpl) Read(ctx context.Context, path string) (*DirectoryState, error) {
	script := psDirectoryHeader + strings.NewReplacer("@@PATH@@", psQuote(path)).Replace(psDirectoryReadBody)
	response, err := d.run(ctx, "read", script)
	if err != nil {
		return nil, err
	}
	var data directoryData
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return nil, &DirectoryError{Kind: DirectoryErrorUnknown, Message: "failed to parse read response data", Cause: err}
	}
	if !data.Found {
		return nil, nil
	}
	return &DirectoryState{Path: path, LastWriteTime: data.LastWriteTime, Attributes: data.Attributes}, nil
}

func (d *DirectoryClientImpl) Delete(ctx context.Context, path string, recursive bool) error {
	script := psDirectoryHeader + strings.NewReplacer("@@PATH@@", psQuote(path), "@@RECURSIVE@@", "$"+psBool(recursive)).Replace(psDirectoryDeleteBody)
	_, err := d.run(ctx, "delete", script)
	return err
}
