// Package winclient: windows_file CRUD implementation over SSH.
//
// Transport invariants (spec T-1..T-4):
//   - File content NEVER appears in the script body. It is streamed as ASCII
//     base64 on stdin via RunPowerShellWithInput and read back with
//     [Console]::In.ReadToEnd(). This keeps psQuote off megabyte payloads,
//     avoids the x4 blow-up of the UTF-16LE base64 script encoding, preserves
//     exact binary fidelity, and keeps the bytes out of -EncodedCommand.
//   - Writes are atomic: content lands in "<dir>\.tf-<guid>.tmp" and is then
//     swapped in. A crash mid-write never leaves a truncated target (EC-13).
//   - Replace() is used when the target already exists because it PRESERVES the
//     destination security descriptor. This is what stops windows_file from
//     clobbering an ACL owned by windows_file_acl (EC-15).
//   - Sharing violations are retried with backoff before surfacing file_locked
//     (EC-7); on Windows this is the dominant source of flaky file writes.
//
// Security invariants:
//   - Every user-supplied string reaching a script goes through psQuote.
//   - The content base64 is validated Go-side before transport.
package winclient

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Compile-time assertion: FileClientImpl satisfies FileClient.
var _ FileClient = (*FileClientImpl)(nil)

// FileClientImpl is the PowerShell/SSH-backed FileClient.
type FileClientImpl struct {
	c *Client
}

// NewFileClient constructs a FileClientImpl wrapping the given SSH Client.
func NewFileClient(c *Client) *FileClientImpl {
	return &FileClientImpl{c: c}
}

// psFileHeader holds every PowerShell helper shared by the file scripts.
const psFileHeader = `
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

# Classify-FileError maps a .NET exception to a FileErrorKind. Win32 codes are
# read from HResult rather than from message text so the mapping is immune to
# the locale of the target host.
function Classify-FileError($Rec) {
  $ex = $Rec.Exception
  while ($null -ne $ex -and $ex -is [System.Management.Automation.MethodInvocationException] -and $null -ne $ex.InnerException) {
    $ex = $ex.InnerException
  }
  if ($ex -is [System.UnauthorizedAccessException])   { return 'permission_denied' }
  if ($ex -is [System.IO.DirectoryNotFoundException]) { return 'path_not_found' }
  if ($ex -is [System.IO.FileNotFoundException])      { return 'not_found' }
  if ($ex -is [System.IO.PathTooLongException])       { return 'invalid_input' }
  if ($ex -is [System.Net.WebException])              { return 'download_failed' }
  if ($ex.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') { return 'download_failed' }
  if ($ex -is [System.IO.IOException]) {
    $code = 0
    try { $code = [int]($ex.HResult -band 0xFFFF) } catch { $code = 0 }
    switch ($code) {
      2   { return 'not_found' }          # ERROR_FILE_NOT_FOUND
      3   { return 'path_not_found' }     # ERROR_PATH_NOT_FOUND
      5   { return 'permission_denied' }  # ERROR_ACCESS_DENIED
      32  { return 'file_locked' }        # ERROR_SHARING_VIOLATION
      33  { return 'file_locked' }        # ERROR_LOCK_VIOLATION
      39  { return 'disk_full' }          # ERROR_HANDLE_DISK_FULL
      112 { return 'disk_full' }          # ERROR_DISK_FULL
    }
    return 'unknown'
  }
  return 'unknown'
}

# Invoke-FileRetry retries only on sharing/lock violations (EC-7): 500ms, 1s, 2s.
function Invoke-FileRetry([scriptblock]$Action) {
  $delays = @(500, 1000, 2000)
  for ($i = 0; $i -le $delays.Length; $i++) {
    try { return (& $Action) }
    catch {
      if ((Classify-FileError $_) -eq 'file_locked' -and $i -lt $delays.Length) {
        Start-Sleep -Milliseconds $delays[$i]
        continue
      }
      throw
    }
  }
}

# Get-FileSha256 opens with FileShare::ReadWrite so hashing a file held open by
# another process (IIS, an antivirus) still succeeds.
function Get-FileSha256([string]$P) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $fs  = [System.IO.File]::Open($P, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  try { $h = $sha.ComputeHash($fs) } finally { $fs.Dispose(); $sha.Dispose() }
  $sb = New-Object System.Text.StringBuilder 64
  foreach ($b in $h) { [void]$sb.Append($b.ToString('x2')) }
  return $sb.ToString()
}

function Get-FileAttrList($A) {
  $out = New-Object System.Collections.ArrayList
  if ($A -band [System.IO.FileAttributes]::Archive)   { [void]$out.Add('archive') }
  if ($A -band [System.IO.FileAttributes]::Hidden)    { [void]$out.Add('hidden') }
  if ($A -band [System.IO.FileAttributes]::ReadOnly)  { [void]$out.Add('readonly') }
  if ($A -band [System.IO.FileAttributes]::System)    { [void]$out.Add('system') }
  if ($A -band [System.IO.FileAttributes]::Temporary) { [void]$out.Add('temporary') }
  return ,([string[]]$out.ToArray())
}

function Build-FileData([string]$P) {
  $fi = New-Object System.IO.FileInfo $P
  $fi.Refresh()
  return [ordered]@{
    found           = $true
    sha256          = (Get-FileSha256 $P)
    size_bytes      = [int64]$fi.Length
    last_write_time = $fi.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
    attributes      = (Get-FileAttrList $fi.Attributes)
  }
}

# Clear-FileReadOnly drops the ReadOnly flag so Replace/Delete can proceed (EC-6).
function Clear-FileReadOnly([string]$P) {
  if ([System.IO.File]::Exists($P)) {
    $a = [System.IO.File]::GetAttributes($P)
    if ($a -band [System.IO.FileAttributes]::ReadOnly) {
      [System.IO.File]::SetAttributes($P, ($a -bxor [System.IO.FileAttributes]::ReadOnly))
    }
  }
}

function Set-FileAttrs([string]$P, [string[]]$Wanted) {
  $val = [System.IO.FileAttributes]::Normal
  foreach ($w in $Wanted) {
    switch ($w) {
      'archive'   { $val = $val -bor [System.IO.FileAttributes]::Archive }
      'hidden'    { $val = $val -bor [System.IO.FileAttributes]::Hidden }
      'readonly'  { $val = $val -bor [System.IO.FileAttributes]::ReadOnly }
      'system'    { $val = $val -bor [System.IO.FileAttributes]::System }
      'temporary' { $val = $val -bor [System.IO.FileAttributes]::Temporary }
    }
  }
  # Normal is only valid on its own.
  if ($val -ne [System.IO.FileAttributes]::Normal) {
    $val = $val -band (-bnot [System.IO.FileAttributes]::Normal)
  }
  [System.IO.File]::SetAttributes($P, $val)
}

# Reset-InheritedAcl is applied ONLY to a freshly created file: it drops any
# explicit ACE carried over from the temp file and restores pure inheritance
# from the parent directory. An existing target never goes through here, so an
# ACL managed by windows_file_acl survives a content update untouched (EC-15).
function Reset-InheritedAcl([string]$P) {
  try {
    $acl = Get-Acl -LiteralPath $P
    $acl.SetAccessRuleProtection($false, $false)
    foreach ($rule in @($acl.Access)) {
      if (-not $rule.IsInherited) { [void]$acl.RemoveAccessRule($rule) }
    }
    Set-Acl -LiteralPath $P -AclObject $acl
  } catch {
    # Non-fatal: the file is written, only inheritance normalisation failed.
  }
}
`

// psFileSetBody is the Set script template.
// Placeholders: @@PATH@@ @@ATTRS@@ @@OVERWRITE@@ @@CREATE_PARENTS@@
// @@EXPECT_SHA@@ @@ACQUIRE@@.
const psFileSetBody = `
& {
  $target = @@PATH@@
  $wanted = @@ATTRS@@
  try {
    if ([System.IO.Directory]::Exists($target)) {
      Emit-Err 'type_conflict' ('path exists and is a directory: ' + $target) @{ path = $target }
      return
    }
    $exists = [System.IO.File]::Exists($target)
    if ($exists -and -not @@OVERWRITE@@) {
      Emit-Err 'already_exists' ('file already exists and overwrite is false: ' + $target) @{ path = $target }
      return
    }
    $dir = [System.IO.Path]::GetDirectoryName($target)
    if ([string]::IsNullOrEmpty($dir)) {
      Emit-Err 'invalid_input' ('path has no parent directory: ' + $target) @{ path = $target }
      return
    }
    if (-not [System.IO.Directory]::Exists($dir)) {
      if (@@CREATE_PARENTS@@) {
        [void][System.IO.Directory]::CreateDirectory($dir)
      } else {
        Emit-Err 'path_not_found' ('parent directory does not exist: ' + $dir) @{ directory = $dir }
        return
      }
    }
    $tmp = [System.IO.Path]::Combine($dir, ('.tf-' + [guid]::NewGuid().ToString('N') + '.tmp'))
    try {
@@ACQUIRE@@
      $expect = @@EXPECT_SHA@@
      if ($expect -ne '') {
        $actual = Get-FileSha256 $tmp
        if ($actual -ne $expect) {
          Emit-Err 'checksum_mismatch' ('checksum mismatch: expected ' + $expect + ', got ' + $actual) @{ expected = $expect; actual = $actual }
          return
        }
      }
      if ($exists) {
        Clear-FileReadOnly $target
        # [NullString]::Value is required here: PowerShell marshals a bare
        # $null to an empty string for a [string] parameter, and Replace()
        # then rejects it with "The path is not of a legal form".
        Invoke-FileRetry { [System.IO.File]::Replace($tmp, $target, [NullString]::Value) }
      } else {
        Invoke-FileRetry { [System.IO.File]::Move($tmp, $target) }
        Reset-InheritedAcl $target
      }
      Set-FileAttrs $target $wanted
      Emit-OK (Build-FileData $target)
    } finally {
      if ([System.IO.File]::Exists($tmp)) {
        Clear-FileReadOnly $tmp
        [System.IO.File]::Delete($tmp)
      }
    }
  } catch {
    Emit-Err (Classify-FileError $_) $_.Exception.Message @{ path = $target }
  }
}
`

// psFileAcquireStdin reads the base64 payload streamed after the script on stdin.
const psFileAcquireStdin = `      $b64 = [Console]::In.ReadToEnd()
      if ($null -eq $b64) { $b64 = '' }
      $bytes = [Convert]::FromBase64String($b64.Trim())
      [System.IO.File]::WriteAllBytes($tmp, $bytes)`

// psFileAcquireDownload downloads on the target host (download_on = "target").
// Placeholders: @@URL@@ @@HEADERS@@ @@SKIPTLS@@.
const psFileAcquireDownload = `      $prevCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
      try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        if (@@SKIPTLS@@) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
        Invoke-WebRequest -Uri @@URL@@ -OutFile $tmp -UseBasicParsing -Headers @@HEADERS@@ -MaximumRedirection 5
      } catch {
        Emit-Err 'download_failed' $_.Exception.Message @{ url = @@URL@@ }
        return
      } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $prevCallback
      }`

// psFileReadBody is the Read script template. Placeholder: @@PATH@@.
// It returns metadata only and never transfers file bytes (decision D-1).
const psFileReadBody = `
& {
  $target = @@PATH@@
  try {
    if ([System.IO.Directory]::Exists($target)) {
      Emit-Err 'type_conflict' ('path exists and is a directory: ' + $target) @{ path = $target }
      return
    }
    if (-not [System.IO.File]::Exists($target)) {
      Emit-OK @{ found = $false }
      return
    }
    Emit-OK (Build-FileData $target)
  } catch {
    Emit-Err (Classify-FileError $_) $_.Exception.Message @{ path = $target }
  }
}
`

// psFileReadContentBody backs ImportState only. Placeholders: @@PATH@@ @@MAXBYTES@@.
const psFileReadContentBody = `
& {
  $target = @@PATH@@
  try {
    if ([System.IO.Directory]::Exists($target)) {
      Emit-Err 'type_conflict' ('path exists and is a directory: ' + $target) @{ path = $target }
      return
    }
    if (-not [System.IO.File]::Exists($target)) {
      Emit-OK @{ found = $false }
      return
    }
    $fi = New-Object System.IO.FileInfo $target
    $fi.Refresh()
    if ([int64]$fi.Length -gt @@MAXBYTES@@) {
      Emit-OK @{ found = $true; truncated = $true; size_bytes = [int64]$fi.Length; sha256 = (Get-FileSha256 $target); content_base64 = '' }
      return
    }
    $bytes = [System.IO.File]::ReadAllBytes($target)
    Emit-OK @{ found = $true; truncated = $false; size_bytes = [int64]$bytes.Length; sha256 = (Get-FileSha256 $target); content_base64 = [Convert]::ToBase64String($bytes) }
  } catch {
    Emit-Err (Classify-FileError $_) $_.Exception.Message @{ path = $target }
  }
}
`

// psFileDeleteBody is the Delete script template. Placeholder: @@PATH@@.
const psFileDeleteBody = `
& {
  $target = @@PATH@@
  try {
    if ([System.IO.Directory]::Exists($target)) {
      Emit-Err 'type_conflict' ('path exists and is a directory: ' + $target) @{ path = $target }
      return
    }
    if (-not [System.IO.File]::Exists($target)) {
      Emit-OK @{ deleted = $false; reason = 'not_found' }
      return
    }
    Clear-FileReadOnly $target
    Invoke-FileRetry { [System.IO.File]::Delete($target) }
    Emit-OK @{ deleted = $true }
  } catch {
    Emit-Err (Classify-FileError $_) $_.Exception.Message @{ path = $target }
  }
}
`

// runFilePowerShell is the package-level hook for test substitution.
// When stdin is empty the plain RunPowerShell path is used.
var runFilePowerShell = func(ctx context.Context, c *Client, script, stdin string) (string, string, error) {
	if stdin == "" {
		return c.RunPowerShell(ctx, script)
	}
	return c.RunPowerShellWithInput(ctx, script, stdin)
}

// filePSResponse is the parsed JSON envelope for file operations.
type filePSResponse struct {
	OK      bool              `json:"ok"`
	Kind    string            `json:"kind,omitempty"`
	Message string            `json:"message,omitempty"`
	Context map[string]string `json:"context,omitempty"`
	Data    json.RawMessage   `json:"data,omitempty"`
}

// fileDataPayload mirrors the JSON object returned by the Set/Read scripts.
// Attributes is json.RawMessage because ConvertTo-Json serialises a
// single-element [string[]] as a bare string.
type fileDataPayload struct {
	Found         bool            `json:"found"`
	SHA256        string          `json:"sha256"`
	SizeBytes     int64           `json:"size_bytes"`
	LastWriteTime string          `json:"last_write_time"`
	Attributes    json.RawMessage `json:"attributes"`
	Truncated     bool            `json:"truncated"`
	ContentBase64 string          `json:"content_base64"`
}

// runScript executes a PS script and parses the JSON envelope.
func (f *FileClientImpl) runScript(ctx context.Context, op, script, stdin string) (*filePSResponse, error) {
	stdout, stderr, err := runFilePowerShell(ctx, f.c, script, stdin)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, &FileError{
				Kind:    FileErrorUnknown,
				Message: fmt.Sprintf("operation %q timed out or was cancelled", op),
				Cause:   ctxErr,
				Context: map[string]string{"operation": op, "host": f.c.cfg.Host},
			}
		}
		return nil, &FileError{
			Kind:    FileErrorUnknown,
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
		return nil, &FileError{
			Kind:    FileErrorUnknown,
			Message: fmt.Sprintf("no JSON envelope returned from %q", op),
			Context: map[string]string{
				"operation": op, "host": f.c.cfg.Host,
				"stderr": truncate(stderr, 2048),
				"stdout": truncate(stdout, 2048),
			},
		}
	}

	var resp filePSResponse
	if jerr := json.Unmarshal([]byte(line), &resp); jerr != nil {
		return nil, &FileError{
			Kind:    FileErrorUnknown,
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
		return &resp, &FileError{Kind: mapFileErrorKind(resp.Kind), Message: resp.Message, Context: ctxMap}
	}
	return &resp, nil
}

// mapFileErrorKind translates the PS-side "kind" string to a typed FileErrorKind.
func mapFileErrorKind(k string) FileErrorKind {
	switch k {
	case string(FileErrorNotFound), string(FileErrorAlreadyExists), string(FileErrorTypeConflict),
		string(FileErrorPathNotFound), string(FileErrorPermission), string(FileErrorLocked),
		string(FileErrorDiskFull), string(FileErrorDownloadFailed), string(FileErrorChecksumMismatch),
		string(FileErrorInvalidInput):
		return FileErrorKind(k)
	default:
		return FileErrorUnknown
	}
}

// psHeadersHashtable renders an HTTP header map as a PowerShell hashtable
// literal. Keys are sorted so the generated script is deterministic (which the
// unit tests rely on), and both keys and values go through psQuote.
func psHeadersHashtable(h map[string]string) string {
	if len(h) == 0 {
		return "@{}"
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, psQuote(k)+" = "+psQuote(h[k]))
	}
	return "@{" + strings.Join(parts, "; ") + "}"
}

// parseFileDataPayload converts the JSON data blob into a *FileState.
// Returns (nil, nil) when found=false.
func parseFileDataPayload(raw json.RawMessage, path string) (*FileState, error) {
	if raw == nil || string(raw) == "null" {
		return nil, nil
	}
	var payload fileDataPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, &FileError{Kind: FileErrorUnknown, Message: "failed to parse file payload", Cause: err}
	}
	if !payload.Found {
		return nil, nil
	}
	attrs, err := parseMultiStringPayload(payload.Attributes)
	if err != nil {
		return nil, &FileError{Kind: FileErrorUnknown, Message: err.Error()}
	}
	return &FileState{
		Path:          path,
		SHA256:        payload.SHA256,
		SizeBytes:     payload.SizeBytes,
		LastWriteTime: payload.LastWriteTime,
		Attributes:    attrs,
	}, nil
}

// buildFileSetScript renders the Set script and returns it together with the
// stdin payload (empty when the target host performs the download itself).
func buildFileSetScript(input FileInput) (script, stdin string, err error) {
	if strings.TrimSpace(input.Path) == "" {
		return "", "", &FileError{Kind: FileErrorInvalidInput, Message: "path must not be empty"}
	}
	attrs, err := NormaliseFileAttributes(input.Attributes)
	if err != nil {
		return "", "", err
	}

	var acquire string
	expectSHA := input.SourceURLSHA256

	if input.DownloadOnTarget {
		if input.SourceURL == "" {
			return "", "", &FileError{Kind: FileErrorInvalidInput,
				Message: `download_on = "target" requires source_url`}
		}
		if expectSHA == "" {
			return "", "", &FileError{Kind: FileErrorInvalidInput,
				Message: `download_on = "target" requires source_url_sha256: without a pinned checksum the provider cannot verify what the host downloaded`}
		}
		acquire = strings.NewReplacer(
			"@@URL@@", psQuote(input.SourceURL),
			"@@HEADERS@@", psHeadersHashtable(input.SourceURLHeaders),
			"@@SKIPTLS@@", "$"+psBool(input.SourceURLInsecureSkipVerify),
		).Replace(psFileAcquireDownload)
	} else {
		if _, verr := ValidateFileContentBase64(input.ContentBase64); verr != nil {
			return "", "", verr
		}
		acquire = psFileAcquireStdin
		stdin = input.ContentBase64
	}

	body := strings.NewReplacer(
		"@@PATH@@", psQuote(input.Path),
		"@@ATTRS@@", "[string[]]"+psQuoteList(attrs),
		"@@OVERWRITE@@", "$"+psBool(input.Overwrite),
		"@@CREATE_PARENTS@@", "$"+psBool(input.CreateParents),
		"@@EXPECT_SHA@@", psQuote(strings.ToLower(expectSHA)),
		"@@ACQUIRE@@", acquire,
	).Replace(psFileSetBody)

	return psFileHeader + "\n" + body, stdin, nil
}

// Set implements FileClient.Set.
func (f *FileClientImpl) Set(ctx context.Context, input FileInput) (*FileState, error) {
	script, stdin, err := buildFileSetScript(input)
	if err != nil {
		return nil, err
	}
	resp, err := f.runScript(ctx, "set", script, stdin)
	if err != nil {
		return nil, err
	}
	state, err := parseFileDataPayload(resp.Data, input.Path)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, &FileError{Kind: FileErrorUnknown,
			Message: "set reported success but returned no file state",
			Context: map[string]string{"path": input.Path}}
	}
	return state, nil
}

// Read implements FileClient.Read. Metadata only, never file bytes (D-1).
// Returns (nil, nil) when the file does not exist (EC-4).
func (f *FileClientImpl) Read(ctx context.Context, path string) (*FileState, error) {
	script := psFileHeader + "\n" + strings.NewReplacer("@@PATH@@", psQuote(path)).Replace(psFileReadBody)
	resp, err := f.runScript(ctx, "read", script, "")
	if err != nil {
		if IsFileError(err, FileErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return parseFileDataPayload(resp.Data, path)
}

// ReadContent implements FileClient.ReadContent.
//
// Reserved for ImportState (decision (b)): it is the only code path allowed to
// pull file bytes back over SSH, and it refuses to do so above maxBytes,
// reporting Truncated instead.
func (f *FileClientImpl) ReadContent(ctx context.Context, path string, maxBytes int64) (*FileContent, error) {
	if maxBytes <= 0 {
		maxBytes = FileImportMaxBytes
	}
	script := psFileHeader + "\n" + strings.NewReplacer(
		"@@PATH@@", psQuote(path),
		"@@MAXBYTES@@", strconv.FormatInt(maxBytes, 10),
	).Replace(psFileReadContentBody)

	resp, err := f.runScript(ctx, "read_content", script, "")
	if err != nil {
		if IsFileError(err, FileErrorNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if resp.Data == nil || string(resp.Data) == "null" {
		return nil, nil
	}
	var payload fileDataPayload
	if jerr := json.Unmarshal(resp.Data, &payload); jerr != nil {
		return nil, &FileError{Kind: FileErrorUnknown, Message: "failed to parse file content payload", Cause: jerr}
	}
	if !payload.Found {
		return nil, nil
	}
	return &FileContent{
		ContentBase64: payload.ContentBase64,
		SizeBytes:     payload.SizeBytes,
		SHA256:        payload.SHA256,
		Truncated:     payload.Truncated,
	}, nil
}

// Delete implements FileClient.Delete. Idempotent (EC-12).
func (f *FileClientImpl) Delete(ctx context.Context, path string) error {
	script := psFileHeader + "\n" + strings.NewReplacer("@@PATH@@", psQuote(path)).Replace(psFileDeleteBody)
	if _, err := f.runScript(ctx, "delete", script, ""); err != nil {
		if IsFileError(err, FileErrorNotFound) {
			return nil
		}
		return err
	}
	return nil
}
