// Guard tests for the shared PowerShell envelope prelude (issue #348).
//
// TestPSEnvelopePrelude_Contents pins the canonical Emit-OK / Emit-Err
// bytes (see envelope_prelude.go versioning rule) while
// TestPSEnvelopePrelude_NoNewDefinitions fails if a new per-file
// Emit-OK / Emit-Err definition appears outside the shared prelude:
// migrations compose the prelude by concatenation, never by re-typing.
package winclient

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestPSEnvelopePrelude_Contents(t *testing.T) {
	for _, want := range []string{
		"$ErrorActionPreference = 'Stop'",
		"$ProgressPreference    = 'SilentlyContinue'",
		"$WarningPreference     = 'SilentlyContinue'",
		"function Emit-OK([object]$Data)",
		"function Emit-Err([string]$Kind, [string]$Message, [hashtable]$Ctx)",
		"ConvertTo-Json -Depth 8 -Compress",
		"if (-not $Ctx) { $Ctx = @{} }",
	} {
		if !strings.Contains(psEnvelopePrelude, want) {
			t.Errorf("psEnvelopePrelude missing %q", want)
		}
	}
	// Go raw-string literals must not contain PowerShell backtick escapes.
	if strings.Contains(psEnvelopePrelude, "`n") || strings.Contains(psEnvelopePrelude, "`t") {
		t.Error("psEnvelopePrelude must not contain PowerShell backtick escape sequences")
	}
	// Session safety (#81): the shared prelude never exits the host session.
	lower := strings.ToLower(psEnvelopePrelude)
	if strings.Contains(lower, "\nexit") || strings.Contains(lower, ";exit") {
		t.Error("psEnvelopePrelude must never call exit (persistent session)")
	}
}

// envelopeDefRe matches a PowerShell function DEFINITION of Emit-OK or
// Emit-Err. It deliberately does not match call sites ("Emit-Err 'kind'")
// or prose mentions in comments. Leading whitespace is tolerated so an
// indented copy cannot evade the guard.
var envelopeDefRe = regexp.MustCompile(`(?m)^\s*function Emit-(OK|Err)\b`)

// envelopePreludeAllowlist names the non-test winclient files still
// permitted to define their own Emit-OK / Emit-Err pair: every resource
// not yet migrated to psEnvelopePrelude, plus the two pre-existing
// shared headers (iis_common.go, storage_common.go) which migrate in a
// later batch. Each migration batch MUST shrink this list; the guard
// fails on any definition outside it.
var envelopePreludeAllowlist = map[string]bool{
	"certificate.go":          true,
	"directory.go":            true,
	"dns_client.go":           true,
	"domain_membership.go":    true,
	"dsc_resource.go":         true,
	"environment_variable.go": true,
	"eventlog.go":             true,
	"feature.go":              true,
	"file.go":                 true,
	"file_acl.go":             true,
	"firewall_profile.go":     true,
	"firewall_rule.go":        true,
	"iis_common.go":           true,
	"installed_software.go":   true,
	"legacy_package.go":       true,
	"local_group.go":          true,
	"local_user.go":           true,
	"mgmtpath.go":             true,
	"net_ip_address.go":       true,
	"net_route.go":            true,
	"network_adapter.go":      true,
	"ntp.go":                  true,
	"os_info.go":              true,
	"power_plan.go":           true,
	"registry_value.go":       true,
	"scheduled_task.go":       true,
	"service.go":              true,
	"smb_share.go":            true,
	"storage_common.go":       true,
	"timezone.go":             true,
	"winget_package.go":       true,
}

// findEnvelopeViolations scans dir for non-test .go files defining
// Emit-OK / Emit-Err outside the shared prelude (envelope_prelude.go)
// and not covered by allow. It returns sorted "file:line" hits.
func findEnvelopeViolations(dir string, allow map[string]bool) []string {
	var out []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{"read dir: " + err.Error()}
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if name == "envelope_prelude.go" || allow[name] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			out = append(out, name+": unreadable: "+err.Error())
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if envelopeDefRe.MatchString(line) {
				out = append(out, name+":"+strconv.Itoa(i+1))
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestFindEnvelopeViolations_Fixtures(t *testing.T) {
	dir := t.TempDir()
	fixtures := map[string]string{
		"migrated.go":      "package winclient\nconst h = psEnvelopePrelude + \"x\"\n",
		"unmigrated.go":    "package winclient\nconst h = `\nfunction Emit-Err([string]$K) { }\n`\n",
		"caller.go":        "package winclient\nvar _ = `Emit-Err 'kind' \"msg\" @{}`\n",
		"comment.go":       "package winclient\n// uses Emit-Err envelope\n",
		"anything_test.go": "package winclient\nconst h = `\nfunction Emit-Err([string]$K) { }\n`\n",
	}
	for name, body := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
	}
	got := findEnvelopeViolations(dir, map[string]bool{"unmigrated.go": true})
	if len(got) != 0 {
		t.Errorf("allowlisted violation must pass, got %v", got)
	}
	got = findEnvelopeViolations(dir, nil)
	if len(got) != 1 || !strings.HasPrefix(got[0], "unmigrated.go:") {
		t.Errorf("non-allowlisted definition must fail, got %v", got)
	}
}

func TestPSEnvelopePrelude_NoNewDefinitions(t *testing.T) {
	if hits := findEnvelopeViolations(".", envelopePreludeAllowlist); len(hits) != 0 {
		t.Errorf("new Emit-OK/Emit-Err definition outside the shared prelude (migrate to psEnvelopePrelude or extend the allowlist only by shrinking it): %v", hits)
	}
}

func TestPSHostnameHeader_UsesSharedPrelude(t *testing.T) {
	if !strings.HasPrefix(psHostnameHeader, psEnvelopePrelude) {
		t.Error("psHostnameHeader must compose the shared psEnvelopePrelude by concatenation")
	}
	for _, want := range []string{
		"function Classify-Hostname",
		"function Read-HostnameState",
	} {
		if !strings.Contains(psHostnameHeader, want) {
			t.Errorf("psHostnameHeader lost its resource-specific helper %q during migration", want)
		}
	}
	if n := strings.Count(psHostnameHeader, "function Emit-Err"); n != 1 {
		t.Errorf("psHostnameHeader must define Emit-Err exactly once (via the prelude), got %d", n)
	}
	if n := strings.Count(psHostnameHeader, "function Emit-OK"); n != 1 {
		t.Errorf("psHostnameHeader must define Emit-OK exactly once (via the prelude), got %d", n)
	}
}
