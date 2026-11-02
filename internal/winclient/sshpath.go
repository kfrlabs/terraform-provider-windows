// Package winclient: shared SSH-connection helpers for lockout-guard scripts.
//
// Several resources that can sever the very SSH session Terraform uses
// (windows_firewall_profile in issue #223, windows_firewall_rule follow-up in
// issue #224) need the same target-side question answered: "which firewall
// profile carries the inbound SSH traffic, and would this change lock us
// out?" The PowerShell fragment and the Go-side pure helpers live here so both
// resources share one implementation instead of drifting apart.
//
// The fragment parses $env:SSH_CONNECTION (set by OpenSSH Server for every
// session as "<client IP> <client port> <server IP> <server port>"), maps the
// server IP to its interface via Get-NetIPAddress, then to the interface's
// network category via Get-NetConnectionProfile. DomainAuthenticated is
// normalised to Domain, matching the firewall profile names.
package winclient

import (
	"fmt"
	"strings"
)

// sshProfilePSFragment is the PowerShell fragment shared by every
// lockout-guard script. It resolves the firewall profile that carries the
// current SSH session and stores it in $sshProfile, or records why it could
// not be determined in $sshProfileError (fail-closed: callers must refuse a
// risky change when $sshProfileError is set instead of silently skipping the
// guard).
//
// Placeholders: none. The fragment defines Get-SSHProfileArtifact-free
// locals only ($sshConn, $sshTokens, $sshServerIP, $sshAlias, $sshProfile,
// $sshProfileError) so embedding scripts can invoke it inline.
const sshProfilePSFragment = `
$sshProfile = $null
$sshProfileError = $null
$sshConn = [string]$env:SSH_CONNECTION
if ([string]::IsNullOrWhiteSpace($sshConn)) {
  $sshProfileError = 'SSH_CONNECTION is not set or empty; cannot determine which firewall profile carries this session'
} else {
  $sshTokens = @($sshConn -split '\s+' | Where-Object { $_ -ne '' })
  if ($sshTokens.Count -lt 4) {
    $sshProfileError = ('SSH_CONNECTION has an unexpected shape (want "<client IP> <client port> <server IP> <server port>"): ' + $sshConn)
  } else {
    $sshServerIP = $sshTokens[2]
    try {
      $sshAddr = Get-NetIPAddress -IPAddress $sshServerIP -ErrorAction Stop | Select-Object -First 1
      $sshAlias = [string]$sshAddr.InterfaceAlias
      if ([string]::IsNullOrWhiteSpace($sshAlias)) {
        $sshProfileError = ('no interface alias found for server IP ' + $sshServerIP)
      } else {
        $sshConnProfile = Get-NetConnectionProfile -InterfaceAlias $sshAlias -ErrorAction Stop | Select-Object -First 1
        $sshCategory = [string]$sshConnProfile.NetworkCategory
        switch ($sshCategory) {
          'Public'              { $sshProfile = 'Public' }
          'Private'             { $sshProfile = 'Private' }
          'DomainAuthenticated' { $sshProfile = 'Domain' }
          default               { $sshProfileError = ('unrecognised network category ' + $sshCategory + ' on interface ' + $sshAlias) }
        }
      }
    } catch {
      $sshProfileError = ('failed to map the SSH server IP to a network profile: ' + [string]$_.Exception.Message)
    }
  }
}
`

// sshConnectionServerIP parses an $env:SSH_CONNECTION value
// ("<client IP> <client port> <server IP> <server port>") and returns the
// server IP (third token). IPv6 addresses contain no whitespace, so a plain
// whitespace split is sufficient. A malformed value yields an error so the
// caller fails closed instead of guarding the wrong address.
func sshConnectionServerIP(sshConnection string) (string, error) {
	tokens := strings.Fields(sshConnection)
	if len(tokens) < 4 {
		return "", fmt.Errorf("SSH_CONNECTION has an unexpected shape (want \"<client IP> <client port> <server IP> <server port>\"): %q", sshConnection)
	}
	if tokens[2] == "" {
		return "", fmt.Errorf("SSH_CONNECTION carries an empty server IP: %q", sshConnection)
	}
	return tokens[2], nil
}

// normalizeNetworkCategory maps a Get-NetConnectionProfile NetworkCategory
// value to the corresponding firewall profile name. DomainAuthenticated is
// the connection-profile spelling of the Domain firewall profile.
func normalizeNetworkCategory(category string) (string, error) {
	switch category {
	case "Public":
		return "Public", nil
	case "Private":
		return "Private", nil
	case "DomainAuthenticated", "Domain":
		return "Domain", nil
	default:
		return "", fmt.Errorf("unrecognised network category %q", category)
	}
}

// firewallRuleCoversProfile reports whether a firewall rule whose Profile
// list is ruleProfiles applies to traffic on sshProfile. A rule with "Any"
// (or an empty list, which Windows treats as Any) covers every profile;
// otherwise the SSH profile must appear verbatim (case-insensitive).
// Exactness is load-bearing: on the lab host the SSH session rides Public
// while OpenSSH-Server-In-TCP covers Private only, and that rule must NOT
// count as coverage.
func firewallRuleCoversProfile(ruleProfiles []string, sshProfile string) bool {
	if len(ruleProfiles) == 0 {
		return true
	}
	for _, p := range ruleProfiles {
		if strings.EqualFold(strings.TrimSpace(p), "Any") {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(p), sshProfile) {
			return true
		}
	}
	return false
}

// sshProviderPort returns the TCP port whose inbound Allow rule the lockout
// guard must look for: the configured SSH port, defaulting to 22 when the
// client carries none (mirrors New, which defaults Port to 22).
func sshProviderPort(port int) int {
	if port <= 0 || port > 65535 {
		return 22
	}
	return port
}
