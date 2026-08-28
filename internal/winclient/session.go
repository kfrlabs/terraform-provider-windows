// Package winclient: persistent PowerShell session over a single SSH
// connection (issue #81).
//
// The remote side runs one long-lived powershell.exe that reads successive
// requests from stdin and frames each response with a sentinel line, instead
// of one connection + one process per call. This amortises costly module
// imports (e.g. ServerManager for windows_feature, ~18s cold) across every
// call in a Terraform run instead of paying them on every single call.
package winclient

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// REPL wire protocol framing. These prefixes are chosen to be vanishingly
// unlikely to collide with real script output: legitimate JSON envelopes and
// PowerShell error text never start with "##WINCLIENT-".
const (
	replReadyPrefix     = "##WINCLIENT-READY:"
	replReadySuffix     = "##"
	replEndStdoutPrefix = "##WINCLIENT-END:"
	replEndStdoutSuffix = "##"
	replEndStderrLine   = "##WINCLIENT-END##"
)

// psReplBootstrap is the fixed script passed via -EncodedCommand. Unlike the
// historical one-shot bootstrap, it never returns on its own: it loops,
// reading one request (two base64 lines: script, then secret input) at a
// time, and frames each response so the client can tell where one call's
// output ends and the next begins.
//
// The secret is redirected onto [Console]::In for the duration of the call
// via [Console]::SetIn, bounded to exactly the decoded secret bytes. This
// means existing scripts' [Console]::In.ReadLine() / ReadToEnd() calls work
// unmodified: ReadToEnd() hits the end of the secret's own MemoryStream, not
// the outer pipe, so it never blocks waiting for the next request.
const psReplBootstrap = `$ErrorActionPreference = 'Stop'
$__wcMarker = [guid]::NewGuid().ToString('N')
[Console]::Out.WriteLine('` + replReadyPrefix + `' + $__wcMarker + '` + replReadySuffix + `')
[Console]::Out.Flush()
while ($true) {
  $__b64Script = [Console]::In.ReadLine()
  if ($null -eq $__b64Script) { break }
  $__b64Secret = [Console]::In.ReadLine()
  if ($null -eq $__b64Secret) { $__b64Secret = '' }
  $__scriptBytes = [Convert]::FromBase64String($__b64Script)
  $__script = [Text.Encoding]::Unicode.GetString($__scriptBytes)
  if ($__b64Secret.Length -gt 0) {
    $__secretBytes = [Convert]::FromBase64String($__b64Secret)
  } else {
    $__secretBytes = [byte[]]::new(0)
  }
  $__secretReader = New-Object IO.StreamReader(New-Object IO.MemoryStream(,$__secretBytes))
  $__prevIn = [Console]::In
  $__status = 0
  [Console]::SetIn($__secretReader)
  try {
    & ([ScriptBlock]::Create($__script))
  } catch {
    $__status = 1
    [Console]::Error.WriteLine(($_ | Out-String))
  } finally {
    [Console]::SetIn($__prevIn)
  }
  [Console]::Out.WriteLine('` + replEndStdoutPrefix + `' + $__status + '` + replEndStdoutSuffix + `')
  [Console]::Out.Flush()
  [Console]::Error.WriteLine('` + replEndStderrLine + `')
  [Console]::Error.Flush()
}
`

// replBootstrapCommand builds the fixed powershell.exe invocation for the
// persistent REPL. Its length does not depend on any script sent later,
// matching the constant-command-line guarantee from #39.
func replBootstrapCommand() string {
	return fmt.Sprintf("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s", encodePowerShell(psReplBootstrap))
}

// encodeReplRequest lays out one request: the base64 (UTF-16LE) script on
// its own line, then the base64 (raw bytes) secret on its own line. Both
// sides are base64 specifically so either can contain arbitrary bytes,
// including newlines, without ambiguity about where one field ends and the
// next begins — unlike the old one-shot layout, where the secret could
// safely be the raw remainder of stdin because the process exited right
// after reading it.
func encodeReplRequest(script, secret string) string {
	return encodePowerShell(script) + "\n" + encodeReplSecret(secret) + "\n"
}

// encodeReplSecret base64-encodes the raw secret bytes (no UTF-16LE
// transform: the secret travels as opaque bytes and existing scripts read it
// back with [Console]::In, exactly as before).
func encodeReplSecret(secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(secret))
}

// readReplResponse reads one framed response from the REPL: stdout lines up
// to the "##WINCLIENT-END:<status>##" marker, then stderr lines up to
// "##WINCLIENT-END##". status is 0 when the script ran to completion, 1 when
// it raised an uncaught error (the persistent-session analogue of the old
// non-zero process exit).
func readReplResponse(stdout, stderr *bufio.Reader) (out, errOut string, status int, err error) {
	var outBuf, errBuf strings.Builder
	for {
		line, rerr := stdout.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(trimmed, replEndStdoutPrefix) && strings.HasSuffix(trimmed, replEndStdoutSuffix) {
			code := strings.TrimSuffix(strings.TrimPrefix(trimmed, replEndStdoutPrefix), replEndStdoutSuffix)
			status, err = strconv.Atoi(code)
			if err != nil {
				return outBuf.String(), errBuf.String(), 0, fmt.Errorf("winclient: malformed REPL end marker %q: %w", trimmed, err)
			}
			break
		}
		outBuf.WriteString(line)
		if rerr != nil {
			return outBuf.String(), errBuf.String(), 0, fmt.Errorf("winclient: REPL session ended before stdout end marker: %w", rerr)
		}
	}
	for {
		line, rerr := stderr.ReadString('\n')
		if strings.TrimRight(line, "\r\n") == replEndStderrLine {
			break
		}
		errBuf.WriteString(line)
		if rerr != nil {
			return outBuf.String(), errBuf.String(), 0, fmt.Errorf("winclient: REPL session ended before stderr end marker: %w", rerr)
		}
	}
	return outBuf.String(), errBuf.String(), status, nil
}

// readReplReady blocks for the REPL's startup handshake line and returns the
// per-session marker it announces. Any other first line (or a closed pipe)
// means the remote side is not our bootstrap — surfaced as an error rather
// than silently treated as script output.
func readReplReady(stdout *bufio.Reader) (marker string, err error) {
	line, err := stdout.ReadString('\n')
	trimmed := strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(trimmed, replReadyPrefix) || !strings.HasSuffix(trimmed, replReadySuffix) {
		if err == nil {
			err = fmt.Errorf("unexpected handshake line %q", trimmed)
		}
		return "", fmt.Errorf("winclient: REPL handshake failed: %w", err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(trimmed, replReadyPrefix), replReadySuffix), nil
}
