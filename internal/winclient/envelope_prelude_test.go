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
		"CurrentThread.CurrentCulture",
		"CurrentThread.CurrentUICulture",
		"InvariantCulture",
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

func TestPSClassifyPrelude_Contents(t *testing.T) {
	for _, want := range []string{
		"function Classify-ByPatterns([string]$Msg, [array]$Table, [string]$Default = 'unknown')",
		"first match wins",
		"$row[1]",
	} {
		if !strings.Contains(psClassifyPrelude, want) {
			t.Errorf("psClassifyPrelude missing %q", want)
		}
	}
	// Table data (patterns) lives per-resource; only the loop is shared.
	if strings.Contains(psClassifyPrelude, "permission_denied") || strings.Contains(psClassifyPrelude, "invalid_name") {
		t.Error("psClassifyPrelude must not hard-code resource kinds; table data stays per-resource")
	}
	if strings.Contains(psClassifyPrelude, "`n") || strings.Contains(psClassifyPrelude, "`t") {
		t.Error("psClassifyPrelude must not contain PowerShell backtick escape sequences")
	}
	lower := strings.ToLower(psClassifyPrelude)
	if strings.Contains(lower, "\nexit") || strings.Contains(lower, ";exit") {
		t.Error("psClassifyPrelude must never call exit (persistent session)")
	}
}

// envelopeDefRe matches a PowerShell function DEFINITION of Emit-OK or
// Emit-Err. It deliberately does not match call sites ("Emit-Err 'kind'")
// or prose mentions in comments. Leading whitespace is tolerated so an
// indented copy cannot evade the guard.
var envelopeDefRe = regexp.MustCompile(`(?m)^\s*function Emit-(OK|Err)\b`)

// envelopePreludeAllowlist names the non-test winclient files still
// permitted to define their own Emit-OK / Emit-Err pair. All headers are
// migrated; the list is intentionally empty. The guard fails on any new
// per-file definition outside the shared prelude.
var envelopePreludeAllowlist = map[string]bool{}

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

func TestPSSharedPreludeHeaders_ComposePrelude(t *testing.T) {
	headers := map[string]string{
		"psHostnameHeader":          psHostnameHeader,
		"psDirectoryHeader":         psDirectoryHeader,
		"psDomainMembershipHeader":  psDomainMembershipHeader,
		"psFeatureHeader":           psFeatureHeader,
		"psOSInfoHeader":            psOSInfoHeader,
		"psSmbShareHeader":          psSmbShareHeader,
		"psNTPHeader":               psNTPHeader,
		"psPowerPlanHeader":         psPowerPlanHeader,
		"psTimezoneHeader":          psTimezoneHeader,
		"psHeader":                  psHeader,
		"lgPsHeader":                lgPsHeader,
		"luPsHeader":                luPsHeader,
		"psEnvVarHeader":            psEnvVarHeader,
		"psRegistryValueHeader":     psRegistryValueHeader,
		"psFileHeader":              psFileHeader,
		"psFileACLHeader":           psFileACLHeader,
		"lpHeader":                  lpHeader,
		"psSTHeader":                psSTHeader,
		"psCertificateHeader":       psCertificateHeader,
		"psDnsClientHeader":         psDnsClientHeader,
		"elPsHeader":                elPsHeader,
		"fpPsHeader":                fpPsHeader,
		"frPsHeader":                frPsHeader,
		"psIISHeader":               psIISHeader,
		"psInstalledSoftwareHeader": psInstalledSoftwareHeader,
		"mgmtPathPSHeader":          mgmtPathPSHeader,
		"psNetIPAddressHeader":      psNetIPAddressHeader,
		"psNetRouteHeader":          psNetRouteHeader,
		"psNetworkAdaptersHeader":   psNetworkAdaptersHeader,
		"psStorageHeader":           psStorageHeader,
		"wpHeader":                  wpHeader,
		"dscPsHeader":               dscPsHeader,
	}
	for name, h := range headers {
		if !strings.HasPrefix(h, psEnvelopePrelude) {
			t.Errorf("%s must compose the shared psEnvelopePrelude by concatenation", name)
		}
		if n := strings.Count(h, "function Emit-Err"); n != 1 {
			t.Errorf("%s must define Emit-Err exactly once (via the prelude), got %d", name, n)
		}
		if n := strings.Count(h, "function Emit-OK"); n != 1 {
			t.Errorf("%s must define Emit-OK exactly once (via the prelude), got %d", name, n)
		}
	}
	// Batch 5 pilots the shared string-classifier table on hostname: the
	// composed header must embed the matcher, or Classify-Hostname fails
	// at PowerShell runtime.
	if !strings.Contains(psHostnameHeader, "function Classify-ByPatterns") {
		t.Error("psHostnameHeader must embed psClassifyPrelude (Classify-ByPatterns)")
	}
	for _, want := range []string{
		"function Classify-Hostname",
		"function Read-HostnameState",
		"function Classify-DirectoryError",
		"function Classify-DomainMembership",
		"function Classify-Feature",
		"function Classify-OSInfo",
		"function Classify-SmbShare",
		"function Classify-NTP",
		"function Classify-PowerPlan",
		"function Classify-Timezone",
		"function Classify([string]$Msg)",
		"function Classify-LG",
		"function Classify-LU",
		"function Get-RegHive",
		"function Classify-FileError",
		"function Classify-FileACLError",
		"function Read-LpInput",
		"function Read-TaskState",
		"function Send-EnvBroadcast",
		"function ConvertTo-CertificateJson",
		"function ConvertTo-DnsClientJson",
		"function Read-EventLogState",
		"function Classify-FirewallProfile",
		"function Classify-FR",
		"function Classify-IIS",
		"function Classify-InstalledSoftware",
		"function Classify-NetIpAddress",
		"function ConvertTo-NetRouteJson",
		"function Classify-NetworkAdapters",
		"function Classify-Storage",
		"function Classify-WG",
		"function Classify-DscResource",
	} {
		found := false
		for _, h := range headers {
			if strings.Contains(h, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("migrated headers lost resource-specific helper %q", want)
		}
	}
}
