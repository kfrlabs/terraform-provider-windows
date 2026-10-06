// Package winclient: persistent PowerShell session over a single SSH
// connection (issue #81).
//
// The remote side runs one long-lived pwsh.exe that reads successive
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
//
// Console encoding is forced to UTF-8 once, before the handshake marker, so
// it covers every write for the whole session rather than being re-applied per
// call (#102): with a redirected stdout [Console]::OutputEncoding is the
// OEM/ANSI code page rather than UTF-8, and every response byte reaches Go
// through [Console]::Out.WriteLine, so non-ASCII text was destroyed on that
// hop before encoding/json ever saw it. Both knobs are set:
// [Console]::OutputEncoding for what PowerShell writes to the console
// (and the decoding of native exes' stdout),
// $OutputEncoding for the outbound pipe. New-Object Text.UTF8Encoding $false
// is the BOM-less encoder — NOT the [Text.Encoding]::UTF8 static property,
// which emits a BOM that would prefix the handshake marker. Both assignments are
// guarded because $ErrorActionPreference is 'Stop': a host that refuses them
// must degrade to the previous behaviour instead of failing the handshake.
const psReplBootstrap = `$ErrorActionPreference = 'Stop'
$__wcUtf8NoBom = New-Object Text.UTF8Encoding $false
try { [Console]::OutputEncoding = $__wcUtf8NoBom } catch { }
try { $OutputEncoding = $__wcUtf8NoBom } catch { }
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

// replBootstrapCommand builds the fixed shell invocation for the
// persistent REPL. Its length does not depend on any script sent later,
// matching the constant-command-line guarantee from #39.
//
// The host is pwsh.exe (PowerShell 7), never powershell.exe (5.1): repeated
// stdin writes to a reused 5.1 session stall server-side in Win32-OpenSSH
// (see ADR-0010), while pwsh sessions serve arbitrarily many sequential
// requests. Hosts without pwsh.exe never reach this command — Client.run
// falls back to the one-shot powershell.exe transport instead.
func replBootstrapCommand() string {
	return fmt.Sprintf("pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand %s", encodePowerShell(psReplBootstrap))
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
// to the "##WINCLIENT-END:<status>##" marker, and stderr lines up to
// "##WINCLIENT-END##". status is 0 when the script ran to completion, 1 when
// it raised an uncaught error (the persistent-session analogue of the old
// non-zero process exit).
//
// The two streams are drained by concurrent goroutines rather than one after
// the other. A script that writes enough combined stdout+stderr to fill the
// SSH channel's flow-control window before its own end marker (routine for a
// "cold" CIM/CDXML module like NetSecurity or LocalAccounts, which can be
// chatty on the error/warning stream) would otherwise deadlock: the remote
// side blocks trying to write the full stream, while a sequential reader is
// still waiting on the other one. The pre-#81 one-process-per-call transport
// avoided this by handing Stdout/Stderr to ssh.Session as io.Writers, which
// Session.Start drains with its own concurrent copies; this restores that
// property for the persistent REPL.
//
// Markers are recognised as a line SUFFIX, not a whole line: redirected
// PowerShell streams may emit output that does not end with a newline (e.g.
// a CLIXML warning blob), so the bootstrap's WriteLine(marker) lands glued
// to that output on the same line. Requiring an exact whole-line match
// misses the marker and hangs forever on a persistent session (no EOF ever
// arrives, unlike the old one-process-per-call transport). Anything
// preceding the marker on its line is kept verbatim as script output. The
// marker is always the last thing written on its stream for the call, so a
// suffix match cannot misfire on script output.
func readReplResponse(stdout, stderr *bufio.Reader) (out, errOut string, status int, err error) {
	type stdoutResult struct {
		out    string
		status int
		err    error
	}
	type stderrResult struct {
		out string
		err error
	}

	stdoutDone := make(chan stdoutResult, 1)
	go func() {
		var outBuf strings.Builder
		for {
			line, rerr := stdout.ReadString('\n')
			trimmed := strings.TrimRight(line, "\r\n")
			if idx := strings.LastIndex(trimmed, replEndStdoutPrefix); idx >= 0 && strings.HasSuffix(trimmed, replEndStdoutSuffix) {
				code := strings.TrimSuffix(trimmed[idx+len(replEndStdoutPrefix):], replEndStdoutSuffix)
				if st, atoiErr := strconv.Atoi(code); atoiErr == nil {
					outBuf.WriteString(trimmed[:idx])
					stdoutDone <- stdoutResult{outBuf.String(), st, nil}
					return
				}
			}
			outBuf.WriteString(line)
			if rerr != nil {
				stdoutDone <- stdoutResult{outBuf.String(), 0, fmt.Errorf("winclient: REPL session ended before stdout end marker: %w", rerr)}
				return
			}
		}
	}()

	stderrDone := make(chan stderrResult, 1)
	go func() {
		var errBuf strings.Builder
		for {
			line, rerr := stderr.ReadString('\n')
			if trimmed := strings.TrimRight(line, "\r\n"); strings.HasSuffix(trimmed, replEndStderrLine) {
				errBuf.WriteString(strings.TrimSuffix(trimmed, replEndStderrLine))
				stderrDone <- stderrResult{errBuf.String(), nil}
				return
			}
			errBuf.WriteString(line)
			if rerr != nil {
				stderrDone <- stderrResult{errBuf.String(), fmt.Errorf("winclient: REPL session ended before stderr end marker: %w", rerr)}
				return
			}
		}
	}()

	so := <-stdoutDone
	se := <-stderrDone
	if so.err != nil {
		return so.out, se.out, 0, so.err
	}
	if se.err != nil {
		return so.out, se.out, so.status, se.err
	}
	return so.out, se.out, so.status, nil
}

// readReplReady blocks for the REPL's startup handshake line and returns the
// per-session marker it announces. Any other first line (or a closed pipe)
// means the remote side is not our bootstrap — surfaced as an error rather
// than silently treated as script output.
func readReplReady(stdout *bufio.Reader) (marker string, err error) {
	line, err := stdout.ReadString('\n')
	trimmed := strings.TrimRight(line, "\r\n")
	// Belt-and-braces for #102: a BOM-emitting encoder would prefix the
	// handshake marker with U+FEFF and break the HasPrefix match.
	trimmed = strings.TrimPrefix(trimmed, "\uFEFF")
	if !strings.HasPrefix(trimmed, replReadyPrefix) || !strings.HasSuffix(trimmed, replReadySuffix) {
		if err == nil {
			err = fmt.Errorf("unexpected handshake line %q", trimmed)
		}
		return "", fmt.Errorf("winclient: REPL handshake failed: %w", err)
	}
	return strings.TrimSuffix(strings.TrimPrefix(trimmed, replReadyPrefix), replReadySuffix), nil
}
