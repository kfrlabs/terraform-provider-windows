// Shared target-side download fragment (issue #174).
//
// Both windows_legacy_package (installer fetch) and windows_file
// (download_on = "target") download over HTTPS from PowerShell running on
// the managed host. The fragment below is the single implementation every
// such download must use, because getting TLS right differs between the
// two PowerShell editions and the persistent REPL shares one process
// across all calls of a run:
//
//   - PowerShell 7 (pwsh.exe, the persistent transport) downloads through
//     HttpClient and IGNORES System.Net.ServicePointManager entirely. The
//     only way to skip certificate validation there is the native
//     -SkipCertificateCheck switch; the PS 5.1 validation callback is a
//     silent no-op.
//   - Windows PowerShell 5.1 downloads through System.Net: the callback
//     honours insecure_skip_verify, and TLS 1.2 must be ensured without
//     dropping the protocols the host already allows — and definitely
//     without enabling the broken TLS 1.0/1.1.
//   - Both the protocol set and the validation callback are process-global.
//     The fragment saves and restores both in finally, so a download never
//     leaks a bypass or a narrowed protocol set into later operations.
package winclient

import "strings"

// psInvokeDownload returns a PowerShell try/finally fragment that downloads
// urlExpr to outFileExpr via Invoke-WebRequest. All four arguments are
// PowerShell expressions evaluated on the target:
//
//   - urlExpr: the URL to fetch.
//   - headersExpr: extra request headers as a hashtable expression, or ""
//     to omit.
//   - skipVerifyExpr: boolean expression honouring insecure_skip_verify.
//   - outFileExpr: destination file expression.
//
// Callers embed the fragment inside their own try/catch: download failures
// surface as terminating errors (ErrorAction Stop) for the caller's catch
// to translate into an Emit-Err envelope.
func psInvokeDownload(urlExpr, headersExpr, skipVerifyExpr, outFileExpr string) string {
	var sb strings.Builder
	sb.WriteString("$__wcPrevProto = [System.Net.ServicePointManager]::SecurityProtocol\n")
	sb.WriteString("$__wcPrevCB = [System.Net.ServicePointManager]::ServerCertificateValidationCallback\n")
	sb.WriteString("$__wcSkipTlsVerify = (" + skipVerifyExpr + ")\n")
	sb.WriteString("$__wcIsCore = $PSVersionTable.PSEdition -eq 'Core'\n")
	sb.WriteString("try {\n")
	sb.WriteString("  if (-not $__wcIsCore) {\n")
	sb.WriteString("    [System.Net.ServicePointManager]::SecurityProtocol = $__wcPrevProto -bor [System.Net.SecurityProtocolType]::Tls12\n")
	sb.WriteString("    if ($__wcSkipTlsVerify) { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }\n")
	sb.WriteString("  }\n")
	sb.WriteString("  $__wcIwrParams = @{ Uri = " + urlExpr + "; OutFile = " + outFileExpr + "; UseBasicParsing = $true; ErrorAction = 'Stop'; MaximumRedirection = 5 }\n")
	if headersExpr != "" {
		sb.WriteString("  $__wcIwrParams['Headers'] = " + headersExpr + "\n")
	}
	sb.WriteString("  if ($__wcIsCore -and $__wcSkipTlsVerify) { $__wcIwrParams['SkipCertificateCheck'] = $true }\n")
	sb.WriteString("  Invoke-WebRequest @__wcIwrParams\n")
	sb.WriteString("} finally {\n")
	sb.WriteString("  [System.Net.ServicePointManager]::SecurityProtocol = $__wcPrevProto\n")
	sb.WriteString("  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $__wcPrevCB\n")
	sb.WriteString("}")
	return sb.String()
}
