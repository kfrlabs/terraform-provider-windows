package winclient

import (
	"strings"
	"testing"
)

// Structural coverage for the shared target-side download fragment
// (issue #174): correct per-edition TLS handling and no process-global
// state leaks.
func TestPsInvokeDownloadCoreBranch(t *testing.T) {
	out := psInvokeDownload("'https://example.invalid/x.msi'", "", "$true", "$out")
	// PowerShell 7 downloads through HttpClient: validation is skipped with
	// the native switch, gated on the Core edition and the opt-out.
	for _, want := range []string{
		"$PSVersionTable.PSEdition -eq 'Core'",
		"SkipCertificateCheck",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fragment missing %q:\n%s", want, out)
		}
	}
}

func TestPsInvokeDownloadDesktopBranch(t *testing.T) {
	out := psInvokeDownload("'https://example.invalid/x.msi'", "", "$false", "$out")
	// Windows PowerShell 5.1 downloads through System.Net: TLS 1.2 is added
	// to the existing protocol set (never replacing it), and the callback
	// honours the opt-out.
	if !strings.Contains(out, "SecurityProtocol = $__wcPrevProto -bor [System.Net.SecurityProtocolType]::Tls12") {
		t.Errorf("fragment must add Tls12 to the saved protocols:\n%s", out)
	}
	if !strings.Contains(out, "ServerCertificateValidationCallback = { $true }") {
		t.Errorf("fragment must honour the opt-out on Desktop:\n%s", out)
	}
}

func TestPsInvokeDownloadRestoresGlobalState(t *testing.T) {
	out := psInvokeDownload("'https://example.invalid/x.msi'", "@{}", "$false", "$out")
	// The persistent REPL shares one process across calls: both globals are
	// saved up front and restored in finally.
	for _, want := range []string{
		"finally {",
		"SecurityProtocol = $__wcPrevProto",
		"ServerCertificateValidationCallback = $__wcPrevCB",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("fragment missing restore %q:\n%s", want, out)
		}
	}
}

func TestPsInvokeDownloadNeverEnablesLegacyTLS(t *testing.T) {
	out := psInvokeDownload("'https://example.invalid/x.msi'", "@{A = 'b'}", "$true", "$out")
	if strings.Contains(out, "Tls11") {
		t.Errorf("fragment must not reference TLS 1.1:\n%s", out)
	}
	if strings.Count(out, "SecurityProtocolType]::Tls12") != 1 {
		t.Errorf("fragment must reference exactly the Tls12 enum value once:\n%s", out)
	}
}

func TestPsInvokeDownloadHeaders(t *testing.T) {
	withHeaders := psInvokeDownload("'https://example.invalid/x.msi'", "@{A = 'b'}", "$false", "$out")
	if !strings.Contains(withHeaders, "$__wcIwrParams['Headers'] = @{A = 'b'}") {
		t.Errorf("headers expression not wired:\n%s", withHeaders)
	}
	withoutHeaders := psInvokeDownload("'https://example.invalid/x.msi'", "", "$false", "$out")
	if strings.Contains(withoutHeaders, "['Headers']") {
		t.Errorf("headers must be omitted when empty:\n%s", withoutHeaders)
	}
}

func TestPsInvokeDownloadSubstitutesExpressions(t *testing.T) {
	out := psInvokeDownload("([string]$cfg.source_url)", "", "([bool]$cfg.insecure_skip_verify)", "$installerPath")
	for _, want := range []string{
		"([string]$cfg.source_url)", "([bool]$cfg.insecure_skip_verify)", "$installerPath",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expression %q not embedded:\n%s", want, out)
		}
	}
	if strings.Contains(out, "@@") {
		t.Errorf("unsubstituted placeholder remains:\n%s", out)
	}
}

// Both call sites must render the shared fragment with no placeholders
// left and no legacy-TLS references.
func TestDownloadCallSitesUseSharedFragment(t *testing.T) {
	script, _, err := buildFileSetScript(FileInput{
		Path:             `C:\f.txt`,
		DownloadOnTarget: true,
		SourceURL:        "https://example.invalid/f.txt",
		SourceURLSHA256:  "sha256:deadbeef",
	})
	if err != nil {
		t.Fatalf("buildFileSetScript: %v", err)
	}
	lp := lpCreateScript()

	for name, rendered := range map[string]string{"windows_file": script, "windows_legacy_package": lp} {
		if strings.Contains(rendered, "@@") {
			t.Errorf("%s: unsubstituted placeholder remains", name)
		}
		for _, want := range []string{"SkipCertificateCheck", "PSEdition", "finally {"} {
			if !strings.Contains(rendered, want) {
				t.Errorf("%s: rendered script missing %q", name, want)
			}
		}
		if strings.Contains(rendered, "Tls11") {
			t.Errorf("%s: rendered script still enables TLS 1.1", name)
		}
	}
	if !strings.Contains(lp, "download_failed") {
		t.Error("windows_legacy_package: download_failed envelope lost in rewrite")
	}
	if !strings.Contains(script, "download_failed") {
		t.Error("windows_file: download_failed envelope lost in rewrite")
	}
}
