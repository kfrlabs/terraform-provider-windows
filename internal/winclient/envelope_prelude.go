// Shared PowerShell envelope prelude (issue #348, batch 1).
//
// psEnvelopePrelude is the canonical Emit-OK / Emit-Err pair every
// winclient PowerShell pipeline uses to report its result as a single JSON
// envelope on stdout. Centralising the two functions here (instead of
// copying them into each per-resource header) means an envelope-protocol
// fix — escaping, a new field, depth handling — is made once.
//
// Batch-1 scope is deliberately Emit-only: per-resource Classify-*
// functions and resource-specific helpers (Read-*State, Invoke-*,
// retry loops) stay in their own headers. A generic classifier is
// deferred to a later batch because existing classifiers take
// incompatible shapes (plain message string, (Msg,FQEI) pairs,
// $Record objects with .Exception/HResult, exit codes).
//
// Versioning rule (ADR-0013): the prelude bytes are covered by
// TestPSEnvelopePrelude_Contents. Changing the canonical bytes (Depth,
// parameter spelling, preference pins) is a conscious, ADR-amended
// decision, never drive-by. Migrated headers MUST compose the prelude by
// string concatenation (never by re-typing the functions) so drift is
// impossible; the guard test TestPSEnvelopePrelude_NoNewDefinitions
// fails if a new per-file Emit-OK / Emit-Err definition appears.
//
// Session safety (#81): the prelude never calls exit and never returns a
// value; it only writes one line to [Console]::Out.
package winclient

// psEnvelopePrelude is the canonical envelope emitter pair. Depth 8
// matches the pre-existing hostname / IIS / storage headers; payloads
// needing deeper serialisation keep their own depth at the call site
// until a later batch canonicalises them with fixture proof.
const psEnvelopePrelude = `
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
`
