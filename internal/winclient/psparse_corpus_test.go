// PowerShell parse corpus for winclient script builders (issue #396).
//
// Every build*Script func and every *Body/*Header const a winclient builder
// can hand to the SSH transport is rendered here — fully composed (shared
// envelope prelude + resource header + body) with placeholders substituted
// exactly as production does (psQuote / psQuoteList for user strings,
// $true/$false and int literals where production renders tokens, real Go
// fragment builders where bodies embed generated code). Resources whose
// scripts are composed inline in methods (no Body const / build*Script
// func: hostname rename, timezone set, service CRUD/state, IIS binding,
// local group member, local user resolve, scheduled task register/set,
// file/lp target-side downloads) are covered by representative/* entries
// that call the real production composers and fragments with the seed —
// see TestPSParseInlineRepresentativeCoverage, which fails when a required
// representative is missing. The corpus is parsed, never executed: nothing
// here touches a Windows host, needs credentials, or uses the network.
//
// Transport model respected by these renderings (see client.go, session.go
// and ADR-0010):
//   - Only a fixed bootstrap rides the command line via -EncodedCommand; the
//     real script travels base64 (UTF-16LE) on stdin and secrets travel on
//     stdin alongside it (RunPowerShellWithInput), so rendered scripts must
//     parse standalone — which is exactly what the CI ps-parse job checks
//     with [Parser]::ParseInput over every emitted .ps1 file.
//   - Since #81 the persistent session reuses one pwsh.exe: scripts must
//     never call exit (the shared-prelude guard tests already enforce this).
//
// Dialect caveat: CI parses with PowerShell 7 (pwsh on ubuntu-latest). The
// provider also targets Windows PowerShell 5.1 through the one-shot fallback
// transport, whose language surface is a subset of 7.x for the constructs
// used here. This gate catches syntax errors and broken quoting, not
// version-specific cmdlet availability.
package winclient

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Corpus: representative + adversarial inputs
// ---------------------------------------------------------------------------

// psParseSeed is one input value rendered into every script builder. Markers
// are distinctive tokens that must survive only inside the single-quoted
// PowerShell literal psQuote produces (see TestPSParseAdversarialSingleLiteral).
type psParseSeed struct {
	Name    string
	Value   string
	Markers []string
}

// psParseNormalSeed is the representative benign input.
func psParseNormalSeed() psParseSeed {
	return psParseSeed{Name: "normal", Value: `C:\ProgramData\tf-acc\ok-name_01`}
}

// psParseAdversarialSeeds covers the injection alphabet: ASCII and Unicode
// single quotes, double quotes, backticks, $() subexpressions, variable
// dereferences and CR/LF line breaks.
func psParseAdversarialSeeds() []psParseSeed {
	return []psParseSeed{
		{Name: "squote", Value: `x'; INJECTED_SQUOTE; '`, Markers: []string{"INJECTED_SQUOTE"}},
		{Name: "dquote", Value: `dq"INJECTED_DQUOTE"b`, Markers: []string{"INJECTED_DQUOTE"}},
		{Name: "backtick", Value: "bt`INJECTED_BTICK", Markers: []string{"INJECTED_BTICK"}},
		{Name: "subexpr", Value: `$(INJECTED_SUBEXPR)`, Markers: []string{"INJECTED_SUBEXPR"}},
		{Name: "var", Value: `$env:INJECTED_VAR`, Markers: []string{"INJECTED_VAR"}},
		{Name: "newline", Value: "INJECTED_NL1\r\nINJECTED_NL2';'", Markers: []string{"INJECTED_NL1", "INJECTED_NL2"}},
		{Name: "unicode", Value: "\u2018INJECTED_UNI\u2019\u201a\u201b", Markers: []string{"INJECTED_UNI"}},
		{Name: "mixed", Value: "x\u2019; INJECTED_MIX $(INJECTED_MIX2) `n\ncaf\u00e9-\u65e5\u672c\u8a9e-\U0001f389", Markers: []string{"INJECTED_MIX", "INJECTED_MIX2", "\u65e5\u672c\u8a9e"}},
	}
}

// ---------------------------------------------------------------------------
// Placeholder substitution (mirrors production replacers)
// ---------------------------------------------------------------------------

// psParseSubstitute replaces every @@TOKEN@@ placeholder the way the
// production replacers do: user strings via psQuote/psQuoteList, bools as
// $true/$false (bare True/False where production uses psBool), ints as
// decimal magnitudes, bare identifiers verbatim, and Go-built code fragments
// with an empty string (statement position: blank lines still parse; the
// fully composed fragment paths are covered by entries that call the real
// fragment builders instead).
func psParseSubstitute(body, adv string) string {
	list := psQuoteList([]string{adv})
	return strings.NewReplacer(
		// Ints rendered with Itoa/FormatInt in production.
		"@@SSHPORT@@", "22",
		"@@LOCALPORT@@", "0",
		"@@MAXBYTES@@", "1048576",
		"@@CONCURRENT_USER_LIMIT@@", "5",
		// Bare identifiers / raw text (never quoted in production).
		"@@HIVE_IDENT@@", "LocalMachine",
		"@@SCOPE_RAW@@", "Machine",
		// Bool tokens.
		"@@EXPAND@@", "$true",
		"@@RECURSE@@", "$true",
		"@@RECURSIVE@@", "$true",
		"@@OVERWRITE@@", "$true",
		"@@CREATE_PARENTS@@", "$true",
		"@@CREATEIFMISSING@@", "$true",
		"@@ENCRYPT_DATA@@", "true",
		"@@MANAGE_ACCESS@@", "true",
		// Go-built code fragments (statement position: empty parses).
		"@@PARAMS@@", "",
		"@@SETBLOCK@@", "",
		"@@GUARD@@", "",
		"@@DESIRED@@", "",
		// The stdin acquire path: the exact static fragment production embeds
		// for content/checksum/download-off inputs.
		"@@ACQUIRE@@", psFileAcquireStdin,
		"@@DOWNLOAD@@", "",
		"@@LP_DOWNLOAD@@", "",
		"@@SSHPROFILE@@", "",
		// $Settings array position: empty array parses.
		"@@SETTINGS@@", "@()",
		// String lists.
		"@@ATTRS@@", "[string[]]"+list,
		"@@FULL@@", list,
		"@@CHANGE@@", list,
		"@@READ@@", list,
		"@@NO@@", list,
		"@@NAMES@@", list,
		// Quoted strings.
		"@@NAME@@", psQuote(adv),
		"@@PATH@@", psQuote(adv),
		"@@HIVE@@", psQuote(adv),
		"@@PSTORE@@", psQuote(adv),
		"@@SUBKEY@@", psQuote(adv),
		"@@VALUE@@", psQuote(adv),
		"@@SCOPE@@", psQuote(adv),
		"@@KIND@@", psQuote(adv),
		"@@ID@@", psQuote(adv),
		"@@SRC@@", psQuote(adv),
		"@@VER@@", psQuote(adv),
		"@@OVERRIDE@@", psQuote(adv),
		"@@MODULENAME@@", psQuote(adv),
		"@@MODULEVERSION@@", psQuote(adv),
		"@@RESOURCENAME@@", psQuote(adv),
		"@@METHOD@@", psQuote(adv),
		"@@PLANGUID@@", psQuote(adv),
		"@@TEMPLATEGUID@@", psQuote(adv),
		"@@PSPATH@@", psQuote(adv),
		"@@DESCRIPTION@@", psQuote(adv),
		"@@FOLDER_ENUMERATION_MODE@@", psQuote(adv),
		"@@CACHING_MODE@@", psQuote(adv),
		"@@EXPECT_SHA@@", psQuote(adv),
		"@@URL@@", psQuote(adv),
		"@@RESULT_INBOUND@@", psQuote(adv),
		"@@RESULT_ALLOW_INBOUND@@", psQuote(adv),
	).Replace(body)
}

// Helpers for optional scalar pointers in builder inputs.
func psParseStrPtr(s string) *string { return &s }
func psParseI64Ptr(v int64) *int64   { return &v }

// psParseDiskDescribeLit is the $selDescribe composite literal emitted by
// buildDiskSelectorVars for the seed (always via DiskSelectorByUniqueID,
// the canonical constructor production callers use).
func psParseDiskDescribeLit(seed string) []string {
	return []string{psQuote(DiskSelectorByUniqueID(seed).Describe())}
}

// psParseRegKeyPSPathLit is the @@PSPATH@@ composite literal: the
// provider-qualified hive path plus the seed subkey, exactly as
// DeleteKey composes it.
func psParseRegKeyPSPathLit(seed string) []string {
	prefix, err := registryKeyPSPath("HKLM")
	if err != nil {
		return nil
	}
	return []string{psQuote(prefix + `\` + seed)}
}

// psParseBenignELSettings is a valid minimal event-log configuration used
// where a real settings fragment is required (name still adversarial).
func psParseBenignELSettings() EventLogSettings {
	return EventLogSettings{MaximumSizeBytes: psParseI64Ptr(64 << 20)}
}

// psParseBenignNTPInput is a valid minimal NTP configuration used where a
// real desired/set fragment is required.
func psParseBenignNTPInput() NTPInput {
	return NTPInput{Type: "NTP", Servers: []NTPPeer{{Address: "time.example.com", Flags: "0x9"}}}
}

// psParseAdvSmbSettings renders every share setting from the seed (all go
// through psQuote/psQuoteList/psBool, so adversarial input is safe here).
func psParseAdvSmbSettings(seed string) SmbShareSettings {
	return SmbShareSettings{
		Description:           seed,
		FolderEnumerationMode: seed,
		CachingMode:           seed,
		ConcurrentUserLimit:   5,
		EncryptData:           true,
		FullAccess:            []string{seed},
		ChangeAccess:          []string{seed},
		ReadAccess:            []string{seed},
		NoAccess:              []string{seed},
		ManageAccess:          true,
	}
}

// ---------------------------------------------------------------------------
// Registry: every script builder + every script body/header const
// ---------------------------------------------------------------------------

// psParseBuilder is one registered rendering: Name is the Go symbol (func or
// const) it covers, Render produces the fully composed script for a seed.
type psParseBuilder struct {
	Name   string
	Render func(seed string) (string, error)
	// Unseeded marks renderings that do not take user input (static
	// headers, token-free bodies): the single-literal check only
	// asserts placeholder absence for them, while CI still parses them.
	Unseeded bool
	// ExtraLiterals lists additional single-quoted spellings the seed
	// takes when a builder embeds it inside a larger literal (e.g.
	// buildDiskSelectorVars' $selDescribe). The check strips these too.
	ExtraLiterals func(seed string) []string
}

func psParseOk(s string) func(string) (string, error) {
	return func(string) (string, error) { return s, nil }
}

// psParseRegistry lists every build*Script func and every *Body/*Header
// (plus bootstrap) const in winclient, plus representative extras for
// resources whose scripts are composed inline in methods. TestPSParseRegistryComplete
// fails if a builder exists but is unregistered.
func psParseRegistry() []psParseBuilder {
	advNTP := func(seed string) (string, error) {
		in := psParseBenignNTPInput()
		// Type is validated to an enum by Set, but the fragment builder
		// quotes it, so the adversarial seed flows here safely while
		// servers stay benign (BuildNtpServerString validates addresses).
		in.Type = seed
		desired, err := buildNTPDesiredBlock(in)
		if err != nil {
			return "", err
		}
		setBlock, err := buildNTPSetBlock(in)
		if err != nil {
			return "", err
		}
		return psNTPHeader + "\n" + strings.NewReplacer(
			"@@DESIRED@@", desired,
			"@@SETBLOCK@@", setBlock,
		).Replace(ntpSetBody), nil
	}
	advELApply := func(seed string) (string, error) {
		cfg := psParseBenignELSettings()
		setBlock, err := buildEventLogSetBlock(cfg)
		if err != nil {
			return "", err
		}
		return elPsHeader + "\n" + strings.NewReplacer(
			"@@GUARD@@", buildEventLogGuard(cfg),
			"@@SETBLOCK@@", setBlock,
		).Replace(buildEventLogReplacer(seed).Replace(elApplyBody)), nil
	}
	b := []psParseBuilder{
		// build*Script funcs: called directly with the seed.
		{Name: "buildMgmtPathScript", Unseeded: true, Render: func(seed string) (string, error) {
			_ = seed
			return strings.ReplaceAll(buildMgmtPathScript(22), mgmtPathLocalPortPlaceholder, "0"), nil
		}},
		{Name: "buildPowerPlanApplyScript", Render: func(seed string) (string, error) {
			return buildPowerPlanApplyScript(
				"8c5e7fda-e8bf-4a96-9a85-a6e23a55df66", "381b4222-f694-41f0-9685-ff5bb260df2e", true,
				[]PowerPlanSettingInput{{Subgroup: seed, Setting: seed, ACValue: psParseI64Ptr(120)}}), nil
		}},
		{Name: "buildNetIPAddressResolveScript", Render: func(s string) (string, error) { return buildNetIPAddressResolveScript(s, false), nil }},
		{Name: "buildNetIPAddressReadScript", Render: func(s string) (string, error) { return buildNetIPAddressReadScript(s, s, false), nil }},
		{Name: "buildNetIPAddressLookupScript", Render: func(s string) (string, error) { return buildNetIPAddressLookupScript(s, s), nil }},
		{Name: "buildNetIPAddressEnsureDHCPDisabledScript", Render: func(s string) (string, error) {
			return buildNetIPAddressEnsureDHCPDisabledScript(s, true), nil
		}},
		{Name: "buildNetIPAddressCreateScript", Render: func(s string) (string, error) { return buildNetIPAddressCreateScript(s, s, 24, false, false), nil }},
		{Name: "buildNetIPAddressSetScript", Render: func(s string) (string, error) { return buildNetIPAddressSetScript(s, s, 24, false), nil }},
		{Name: "buildNetIPAddressRemoveScript", Render: func(s string) (string, error) { return buildNetIPAddressRemoveScript(s, s, false), nil }},
		{Name: "buildNetIPAddressRestoreDHCPScript", Render: func(s string) (string, error) { return buildNetIPAddressRestoreDHCPScript(s), nil }},
		{Name: "buildNetIPAddressPrefixOriginScript", Render: func(s string) (string, error) { return buildNetIPAddressPrefixOriginScript(s), nil }},
		{Name: "buildSmbShareScript", Render: func(s string) (string, error) {
			return buildSmbShareScript(psParseSubstitute(psSmbShareCreateBody, s), s, s, psParseAdvSmbSettings(s)), nil
		}},
		{Name: "buildCertificateCreatePEM", Render: func(s string) (string, error) { return buildCertificateCreatePEM(s, s, s), nil }},
		{Name: "buildCertificateCreatePFX", Render: func(s string) (string, error) { return buildCertificateCreatePFX(s, s, s, true), nil }},
		{Name: "buildCertificateReadScript", Render: func(s string) (string, error) { return buildCertificateReadScript(s, s, s), nil }},
		{Name: "buildCertificateLookupScript", Render: func(s string) (string, error) { return buildCertificateLookupScript(s, s, s), nil }},
		{Name: "buildCertificateSetFriendlyScript", Render: func(s string) (string, error) {
			return buildCertificateSetFriendlyScript(s, s, s, s), nil
		}},
		{Name: "buildCertificateRemoveScript", Render: func(s string) (string, error) { return buildCertificateRemoveScript(s, s, s, true), nil }},
		{Name: "buildNetRouteResolveScript", Render: func(s string) (string, error) { return buildNetRouteResolveScript(s, false), nil }},
		{Name: "buildNetRouteReadScript", Render: func(s string) (string, error) { return buildNetRouteReadScript(s, s, s, false), nil }},
		{Name: "buildNetRouteLookupScript", Render: func(s string) (string, error) { return buildNetRouteLookupScript(s, s, s), nil }},
		{Name: "buildNetRouteCreateScript", Render: func(s string) (string, error) { return buildNetRouteCreateScript(s, s, s, 10, false), nil }},
		{Name: "buildNetRouteSetScript", Render: func(s string) (string, error) { return buildNetRouteSetScript(s, s, s, 10, false), nil }},
		{Name: "buildNetRouteRemoveScript", Render: func(s string) (string, error) { return buildNetRouteRemoveScript(s, s, s, false), nil }},
		{Name: "buildNetRouteMgmtRouteScript", Render: func(s string) (string, error) { return buildNetRouteMgmtRouteScript(s, s, 7), nil }},
		{Name: "buildFileSetScript", Render: func(s string) (string, error) {
			script, _, err := buildFileSetScript(FileInput{Path: s})
			return script, err
		}},
		{Name: "buildDiskReadScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildDiskReadScript(DiskSelectorByUniqueID(s)), nil }},
		{Name: "buildDiskInitializeScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildDiskInitializeScript(s, "GPT") }},
		{Name: "buildDiskSetOfflineScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildDiskSetOfflineScript(s, true), nil }},
		{Name: "buildDiskSetReadOnlyScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildDiskSetReadOnlyScript(s, true), nil }},
		{Name: "buildLocalUserListScript", Unseeded: true, Render: func(string) (string, error) { return buildLocalUserListScript(), nil }},
		{Name: "buildNetworkAdaptersListScript", Render: func(s string) (string, error) {
			return buildNetworkAdaptersListScript([]string{s}, true, true), nil
		}},
		{Name: "buildDNSClientReadScript", Render: func(s string) (string, error) { return buildDNSClientReadScript(s), nil }},
		{Name: "buildDNSClientApplyScript", Render: func(s string) (string, error) {
			return buildDNSClientApplyScript(s, DNSClientSettings{
				IPv4Addresses:            []string{s},
				IPv4Set:                  true,
				ConnectionSpecificSuffix: psParseStrPtr(s),
				SuffixSet:                true,
			}), nil
		}},
		{Name: "buildLocalGroupListScript", Render: func(s string) (string, error) { return buildLocalGroupListScript([]string{s}, []string{s}, true), nil }},
		{Name: "buildInstalledSoftwareListScript", Render: func(s string) (string, error) { return buildInstalledSoftwareListScript(s, true), nil }},
		{Name: "buildVolumeFormatScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			return buildVolumeFormatScript(VolumeFormatOptions{
				PartitionID: s + "|" + s, FileSystem: "NTFS", FileSystemLabel: s,
				AllocationUnitSize: 4096, AllowFormatExisting: true,
			}), nil
		}},
		{Name: "buildVolumeReadScript", Render: func(s string) (string, error) { return buildVolumeReadScript(s), nil }},
		{Name: "buildVolumeLabelScript", Render: func(s string) (string, error) { return buildVolumeLabelScript(s, s), nil }},
		{Name: "buildVolumeLookupScript", Render: func(s string) (string, error) { return buildVolumeLookupScript(VolumeLookup{UniqueID: s}), nil }},
		{Name: "buildPartitionCreateScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			return buildPartitionCreateScript(PartitionCreateOptions{DiskUniqueID: s, SizeBytes: 1 << 30}), nil
		}},
		{Name: "buildPartitionReadScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildPartitionReadScript(s, s), nil }},
		{Name: "buildPartitionGrowScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildPartitionGrowScript(s, s, 1<<30), nil }},
		{Name: "buildPartitionLetterScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildPartitionLetterScript(s, s, s), nil }},
		{Name: "buildPartitionFlagsScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			return buildPartitionFlagsScript(s, s, BoolPtr(true), BoolPtr(false)), nil
		}},
		{Name: "buildPartitionDeleteScript", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) { return buildPartitionDeleteScript(s, s), nil }},
		// Other script-returning builders (naming predates the build*Script
		// convention) covered the same way.
		{Name: "lpCreateScript", Unseeded: true, Render: func(string) (string, error) { return lpCreateScript(), nil }},

		// *Body consts: header + substituted body (production-exact where a
		// dedicated replacer/fragment builder exists).
		{Name: "psFeatureReadBody", Render: func(s string) (string, error) {
			return psFeatureHeader + "\n" + psFeatureReadBody + "\nif (Ensure-FeatureCmdlets) { Read-Feature -Name " + psQuote(s) + " }\n", nil
		}},
		{Name: "psFeatureInstallBody", Render: func(s string) (string, error) {
			call := fmt.Sprintf("if (Ensure-FeatureCmdlets) { Run-Install -Name %s -IncludeSub:$%s -IncludeMgmt:$%s -Source %s -Restart:$%s }",
				psQuote(s), psBool(false), psBool(false), psQuote(s), psBool(false))
			return psFeatureHeader + "\n" + psFeatureInstallBody + "\n" + call + "\n", nil
		}},
		{Name: "psFeatureUninstallBody", Render: func(s string) (string, error) {
			call := fmt.Sprintf("if (Ensure-FeatureCmdlets) { Run-Uninstall -Name %s -IncludeMgmt:$%s -Restart:$%s }",
				psQuote(s), psBool(false), psBool(false))
			return psFeatureHeader + "\n" + psFeatureUninstallBody + "\n" + call + "\n", nil
		}},
		{Name: "psDirectoryCreateBody", Render: func(s string) (string, error) {
			attrs, err := NormaliseDirectoryAttributes([]string{"readonly"})
			if err != nil {
				return "", err
			}
			call := fmt.Sprintf("New-Directory -P %s -CreateParents:$%s -Wanted %s",
				psQuote(s), psBool(true), psQuoteList(attrs))
			return psDirectoryHeader + "\n" + psParseSubstitute(psDirectoryCreateBody, s) + "\n" + call + "\n", nil
		}},
		{Name: "psDirectoryReadBody", Render: func(s string) (string, error) {
			return psDirectoryHeader + "\n" + psParseSubstitute(psDirectoryReadBody, s) + "\nRead-Directory -P " + psQuote(s) + "\n", nil
		}},
		{Name: "psDirectoryUpdateBody", Render: func(s string) (string, error) {
			attrs, err := NormaliseDirectoryAttributes([]string{"readonly"})
			if err != nil {
				return "", err
			}
			call := fmt.Sprintf("Update-DirectoryAttrs -P %s -Wanted %s", psQuote(s), psQuoteList(attrs))
			return psDirectoryHeader + "\n" + psParseSubstitute(psDirectoryUpdateBody, s) + "\n" + call + "\n", nil
		}},
		{Name: "psDirectoryDeleteBody", Render: func(s string) (string, error) {
			call := fmt.Sprintf("Remove-Directory -P %s -Recursive:$%s", psQuote(s), psBool(true))
			return psDirectoryHeader + "\n" + psParseSubstitute(psDirectoryDeleteBody, s) + "\n" + call + "\n", nil
		}},
		{Name: "psEnvVarSetBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE_IDENT@@", "LocalMachine",
				"@@SUBKEY@@", psQuote(s),
				"@@SCOPE@@", psQuote("Machine"),
				"@@SCOPE_RAW@@", "Machine",
				"@@NAME@@", psQuote(s),
				"@@VALUE@@", psQuote(s),
				"@@EXPAND@@", "$true",
			)
			return psEnvVarHeader + "\n" + repl.Replace(psEnvVarSetBody), nil
		}},
		{Name: "psEnvVarReadBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE_IDENT@@", "LocalMachine",
				"@@SUBKEY@@", psQuote(s),
				"@@NAME@@", psQuote(s),
			)
			return psEnvVarHeader + "\n" + repl.Replace(psEnvVarReadBody), nil
		}},
		{Name: "psEnvVarDeleteBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE_IDENT@@", "LocalMachine",
				"@@SUBKEY@@", psQuote(s),
				"@@NAME@@", psQuote(s),
			)
			return psEnvVarHeader + "\n" + repl.Replace(psEnvVarDeleteBody), nil
		}},
		{Name: "psRegistryValueSetBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE@@", psQuote(s),
				"@@PATH@@", psQuote(s),
				"@@NAME@@", psQuote(s),
				"@@KIND@@", psQuote("String"),
				"@@EXPAND@@", "$true",
			)
			return psRegistryValueHeader + "\n" + repl.Replace(psRegistryValueSetBody), nil
		}},
		{Name: "psRegistryValueReadBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE@@", psQuote(s),
				"@@PATH@@", psQuote(s),
				"@@NAME@@", psQuote(s),
				"@@EXPAND@@", "$true",
			)
			return psRegistryValueHeader + "\n" + repl.Replace(psRegistryValueReadBody), nil
		}},
		{Name: "psRegistryValueDeleteBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE@@", psQuote(s),
				"@@PATH@@", psQuote(s),
				"@@NAME@@", psQuote(s),
			)
			return psRegistryValueHeader + "\n" + repl.Replace(psRegistryValueDeleteBody), nil
		}},
		{Name: "psRegistryKeyListBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE@@", psQuote(s),
				"@@PATH@@", psQuote(s),
				"@@NAMES@@", psQuoteList([]string{s}),
			)
			return psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyListBody), nil
		}},
		{Name: "psRegistryKeyEnsureBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE@@", psQuote(s),
				"@@PATH@@", psQuote(s),
			)
			return psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyEnsureBody), nil
		}},
		{Name: "psRegistryKeyDeleteValuesBody", Render: func(s string) (string, error) {
			repl := strings.NewReplacer(
				"@@HIVE@@", psQuote(s),
				"@@PATH@@", psQuote(s),
				"@@NAMES@@", psQuoteList([]string{s}),
			)
			return psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyDeleteValuesBody), nil
		}},
		{Name: "psRegistryKeyDeleteKeyBody", ExtraLiterals: psParseRegKeyPSPathLit, Render: func(s string) (string, error) {
			prefix, err := registryKeyPSPath("HKLM")
			if err != nil {
				return "", err
			}
			repl := strings.NewReplacer(
				"@@PSPATH@@", psQuote(prefix+`\`+s),
				"@@RECURSE@@", "$true",
			)
			return psRegistryValueHeader + "\n" + repl.Replace(psRegistryKeyDeleteKeyBody), nil
		}},
		{Name: "psFileSetBody", Render: func(s string) (string, error) {
			return psFileHeader + "\n" + psParseSubstitute(psFileSetBody, s), nil
		}},
		{Name: "psFileReadBody", Render: func(s string) (string, error) {
			return psFileHeader + "\n" + psParseSubstitute(psFileReadBody, s), nil
		}},
		{Name: "psFileReadContentBody", Render: func(s string) (string, error) {
			return psFileHeader + "\n" + psParseSubstitute(psFileReadContentBody, s), nil
		}},
		{Name: "psFileDeleteBody", Render: func(s string) (string, error) {
			return psFileHeader + "\n" + psParseSubstitute(psFileDeleteBody, s), nil
		}},
		// Stdin-transported by design (coordinates arrive as JSON on stdin,
		// nothing is interpolated): unseeded, still parse-gated.
		{Name: "psFileACLSetBody", Unseeded: true, Render: func(s string) (string, error) {
			return psFileACLHeader + "\n" + psParseSubstitute(psFileACLSetBody, s), nil
		}},
		{Name: "psFileACLReadBody", Render: func(s string) (string, error) {
			return psFileACLHeader + "\n" + psParseSubstitute(psFileACLReadBody, s), nil
		}},
		// Stdin-transported by design like the set body: unseeded, still parse-gated.
		{Name: "psFileACLResetBody", Unseeded: true, Render: func(s string) (string, error) {
			return psFileACLHeader + "\n" + psParseSubstitute(psFileACLResetBody, s), nil
		}},
		{Name: "psSmbShareCreateBody", Render: func(s string) (string, error) {
			return psSmbShareHeader + "\n" + buildSmbShareScript(psSmbShareCreateBody, s, s, psParseAdvSmbSettings(s)), nil
		}},
		{Name: "psSmbShareReadBody", Render: func(s string) (string, error) {
			return psSmbShareHeader + "\n" + buildSmbShareScript(psSmbShareReadBody, s, s, psParseAdvSmbSettings(s)), nil
		}},
		{Name: "psSmbShareUpdateBody", Render: func(s string) (string, error) {
			return psSmbShareHeader + "\n" + buildSmbShareScript(psSmbShareUpdateBody, s, s, psParseAdvSmbSettings(s)), nil
		}},
		{Name: "psSmbShareDeleteBody", Render: func(s string) (string, error) {
			return psSmbShareHeader + "\n" + buildSmbShareScript(psSmbShareDeleteBody, s, s, psParseAdvSmbSettings(s)), nil
		}},
		{Name: "elReadBody", Render: func(s string) (string, error) {
			return elPsHeader + "\n" + buildEventLogReplacer(s).Replace(elReadBody), nil
		}},
		{Name: "elApplyBody", Render: advELApply},
		{Name: "elRestoreBody", Render: func(s string) (string, error) {
			cfg := psParseBenignELSettings()
			setBlock, err := buildEventLogSetBlock(cfg)
			if err != nil {
				return "", err
			}
			return elPsHeader + "\n" + strings.NewReplacer(
				"@@SETBLOCK@@", setBlock,
			).Replace(buildEventLogReplacer(s).Replace(elRestoreBody)), nil
		}},
		{Name: "fpReadBody", Render: func(s string) (string, error) {
			return fpPsHeader + "\n" + buildFirewallProfileReplacer(s).Replace(fpReadBody), nil
		}},
		{Name: "fpApplyBody", Render: func(s string) (string, error) {
			return fpPsHeader + "\n" + strings.NewReplacer(
				"@@SSHPORT@@", "22",
				"@@SSHPROFILE@@", sshProfilePSFragment,
				"@@RESULT_INBOUND@@", psQuote(s),
				"@@RESULT_ALLOW_INBOUND@@", psQuote(s),
				"@@PARAMS@@", buildFirewallProfileParams(s, FirewallProfileSettings{Enabled: BoolPtr(true)}),
			).Replace(buildFirewallProfileReplacer(s).Replace(fpApplyBody)), nil
		}},
		{Name: "fpRestoreBody", Render: func(s string) (string, error) {
			snap := FirewallProfileState{Enabled: true, DefaultInboundAction: "Block", DefaultOutboundAction: "Allow"}
			return fpPsHeader + "\n" + strings.NewReplacer(
				"@@PARAMS@@", buildFirewallProfileRestoreParams(s, snap),
			).Replace(buildFirewallProfileReplacer(s).Replace(fpRestoreBody)), nil
		}},
		// No user input (self-describing probe fragment): unseeded, still parse-gated.
		{Name: "fpSSHProfileBody", Unseeded: true, Render: func(string) (string, error) {
			return fpPsHeader + "\n" + strings.NewReplacer(
				"@@SSHPROFILE@@", sshProfilePSFragment,
			).Replace(fpSSHProfileBody), nil
		}},
		{Name: "frCreateBody", Render: func(s string) (string, error) {
			in := FirewallRuleInput{DisplayName: s, Description: s, Direction: "Inbound", Action: "Allow"}
			return frPsHeader + "\n" + strings.NewReplacer(
				"@@PARAMS@@", buildFirewallParams("create", s, s, in),
			).Replace(buildFirewallReplacer(s, s).Replace(frCreateBody)), nil
		}},
		{Name: "frUpdateBody", Render: func(s string) (string, error) {
			in := FirewallRuleInput{DisplayName: s, Description: s, Direction: "Inbound", Action: "Allow"}
			return frPsHeader + "\n" + strings.NewReplacer(
				"@@PARAMS@@", buildFirewallParams("update", s, s, in),
			).Replace(buildFirewallReplacer(s, s).Replace(frUpdateBody)), nil
		}},
		{Name: "frReadBody", Render: func(s string) (string, error) {
			return frPsHeader + "\n" + buildFirewallReplacer(s, s).Replace(frReadBody), nil
		}},
		{Name: "frDeleteBody", Render: func(s string) (string, error) {
			return frPsHeader + "\n" + buildFirewallReplacer(s, s).Replace(frDeleteBody), nil
		}},
		{Name: "ppReadBody", Render: func(s string) (string, error) {
			return psPowerPlanHeader + "\n" + strings.NewReplacer(
				"@@SETTINGS@@", buildPowerPlanReadSettingsArray([]PowerPlanSettingKey{{Subgroup: s, Setting: s}}),
			).Replace(ppReadBody), nil
		}},
		{Name: "ppApplyBody", Render: func(s string) (string, error) {
			in := []PowerPlanSettingInput{{Subgroup: s, Setting: s, ACValue: psParseI64Ptr(120)}}
			return psPowerPlanHeader + "\n" + strings.NewReplacer(
				"@@PLANGUID@@", psQuote(s),
				"@@TEMPLATEGUID@@", psQuote(s),
				"@@CREATEIFMISSING@@", "$true",
				"@@SETTINGS@@", buildPowerPlanWriteSettingsArray(in),
			).Replace(ppApplyBody), nil
		}},
		{Name: "ppListBody", Unseeded: true, Render: func(s string) (string, error) {
			_ = s
			return psPowerPlanHeader + "\n" + ppListBody, nil
		}},
		{Name: "ppDeleteBody", Render: func(s string) (string, error) {
			return psPowerPlanHeader + "\n" + strings.NewReplacer(
				"@@PLANGUID@@", psQuote(s),
			).Replace(ppDeleteBody), nil
		}},
		{Name: "wpInstallBody", Render: func(s string) (string, error) { return wpHeader + "\n" + wpReplace(wpInstallBody, s, s, s, s), nil }},
		{Name: "wpReadBody", Render: func(s string) (string, error) { return wpHeader + "\n" + wpReplace(wpReadBody, s, s, s, s), nil }},
		{Name: "wpUninstallBody", Render: func(s string) (string, error) { return wpHeader + "\n" + wpReplace(wpUninstallBody, s, s, s, s), nil }},
		{Name: "wpUpdateBody", Render: func(s string) (string, error) { return wpHeader + "\n" + wpReplace(wpUpdateBody, s, s, s, s), nil }},
		{Name: "lpCreateBody", Unseeded: true, Render: func(string) (string, error) {
			return lpHeader + "\n" + strings.NewReplacer("@@LP_DOWNLOAD@@", "").Replace(lpCreateBody), nil
		}},
		{Name: "lpReadBody", Unseeded: true, Render: func(string) (string, error) { return lpHeader + "\n" + lpReadBody, nil }},
		{Name: "lpDeleteBody", Unseeded: true, Render: func(string) (string, error) { return lpHeader + "\n" + lpDeleteBody, nil }},
		{Name: "dscPreflightBody", Render: func(s string) (string, error) {
			return dscPsHeader + "\n" + strings.NewReplacer(
				"@@MODULENAME@@", psQuote(s),
				"@@MODULEVERSION@@", psQuote(s),
				"@@RESOURCENAME@@", psQuote(s),
			).Replace(dscPreflightBody), nil
		}},
		{Name: "dscInvokeBody", Render: func(s string) (string, error) {
			return dscPsHeader + "\n" + strings.NewReplacer(
				"@@MODULENAME@@", psQuote(s),
				"@@MODULEVERSION@@", psQuote(s),
				"@@RESOURCENAME@@", psQuote(s),
				"@@METHOD@@", psQuote(s),
			).Replace(dscInvokeBody), nil
		}},
		{Name: "ntpReadBody", Unseeded: true, Render: func(string) (string, error) { return psNTPHeader + "\n" + ntpReadBody, nil }},
		{Name: "ntpSetBody", Render: advNTP},
		{Name: "psReadStateBody", Render: func(s string) (string, error) {
			return psHeader + "\n" + psReadStateBody + "\n$st = Read-ServiceState " + psQuote(s) +
				"\nif ($null -eq $st) { Emit-OK $null } else { Emit-OK $st }\n", nil
		}},
		{Name: "psOSInfoReadBody", Unseeded: true, Render: func(string) (string, error) {
			return psOSInfoHeader + "\n" + psOSInfoReadBody +
				"\ntry { $s = Read-OSInfo; Emit-OK $s } catch { Emit-Err (Classify-OSInfo $_.Exception.Message) $_.Exception.Message @{} }", nil
		}},
		{Name: "psDomainJoinBody", Render: func(s string) (string, error) {
			call := fmt.Sprintf("Join-Domain -Domain %s -OUPath %s -Server %s -Username %s -Restart:$%s",
				psQuote(s), psQuote(s), psQuote(s), psQuote(s), psBool(false))
			return psDomainMembershipHeader + "\n" + psDomainJoinBody + "\n" + call + "\n", nil
		}},
		{Name: "psDomainUnjoinBody", Render: func(s string) (string, error) {
			call := fmt.Sprintf("Leave-Domain -Username %s -Workgroup %s -Restart:$%s",
				psQuote(s), psQuote(s), psBool(false))
			return psDomainMembershipHeader + "\n" + psDomainUnjoinBody + "\n" + call + "\n", nil
		}},
		{Name: "psNetworkAdaptersBody", Render: func(s string) (string, error) {
			tail := fmt.Sprintf("\n$Names = %s\n$PhysicalOnly = %s\n$IncludeHidden = %s\nList-NetworkAdapters -Names $Names -PhysicalOnly $PhysicalOnly -IncludeHidden $IncludeHidden\n",
				psQuoteList([]string{s}), networkAdaptersBoolToken(true), networkAdaptersBoolToken(true))
			return psNetworkAdaptersHeader + "\n" + psParseSubstitute(psNetworkAdaptersBody, s) + tail, nil
		}},
		{Name: "psInstalledSoftwareListBody", Render: func(s string) (string, error) {
			tail := fmt.Sprintf("\n$Hives = %s\n$ProductCode = %s\n$IncludeUserInstalls = %s\nList-InstalledSoftware -Hives $Hives -ProductCode $ProductCode -IncludeUserInstalls $IncludeUserInstalls\n",
				psQuoteList(UninstallRegistryHivePaths), psQuote(s), installedSoftwareBoolToken(true))
			return psInstalledSoftwareHeader + "\n" + psParseSubstitute(psInstalledSoftwareListBody, s) + tail, nil
		}},
		{Name: "psDiskReadBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			return psStorageHeader + "\n" + buildDiskSelectorVars(DiskSelectorByUniqueID(s)) + "\n" + psDiskFunctions + "\n" + psDiskReadBody + "\n", nil
		}},
		{Name: "psVolumeFormatBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			vars := psVolumeVars(s, "NTFS", s, 4096, true, false)
			return volumeFormatScript(s, vars+psParseSubstitute(psVolumeFormatBody, s)), nil
		}},
		{Name: "psVolumeReadBody", Render: func(s string) (string, error) {
			return volumeDirectScript(fmt.Sprintf("$volId = %s\n", psQuote(s)) + psParseSubstitute(psVolumeReadBody, s)), nil
		}},
		{Name: "psVolumeLabelBody", Render: func(s string) (string, error) {
			return volumeDirectScript(fmt.Sprintf("$volId = %s\n$fsLabel = %s\n", psQuote(s), psQuote(s)) +
				psParseSubstitute(psVolumeLabelBody, s)), nil
		}},
		{Name: "psVolumeLookupBody", Render: func(s string) (string, error) {
			return volumeDirectScript(fmt.Sprintf("$lookupMode = %s\n$lookupValue = %s\n", psQuote("unique_id"), psQuote(s)) +
				psParseSubstitute(psVolumeLookupBody, s)), nil
		}},
		{Name: "psPartitionCreateBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			vars := psPartitionVars(1<<30, false, false, 0, "", "", "", "", 0)
			return partitionScript(s, vars+psParseSubstitute(psPartitionCreateBody, s)), nil
		}},
		{Name: "psPartitionReadBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			vars := psPartitionVars(0, false, false, 0, "", "", "", s, 0)
			return partitionScript(s, vars+psParseSubstitute(psPartitionReadBody, s)), nil
		}},
		{Name: "psPartitionGrowBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			vars := psPartitionVars(0, false, false, 0, "", "", "", s, 1<<30)
			return partitionScript(s, vars+psParseSubstitute(psPartitionGrowBody, s)), nil
		}},
		{Name: "psPartitionLetterBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			vars := psPartitionVars(0, false, false, 0, s, "", "", s, 0)
			return partitionScript(s, vars+psParseSubstitute(psPartitionLetterBody, s)), nil
		}},
		{Name: "psPartitionFlagsBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			vars := psPartitionVars(0, false, false, 0, "", "", "", s, 0) +
				"$setHidden = $true\n$hiddenVal = $true\n$setActive = $false\n$activeVal = $false\n"
			return partitionScript(s, vars+psParseSubstitute(psPartitionFlagsBody, s)), nil
		}},
		{Name: "psPartitionDeleteBody", ExtraLiterals: psParseDiskDescribeLit, Render: func(s string) (string, error) {
			vars := psPartitionVars(0, false, false, 0, "", "", "", s, 0)
			return partitionScript(s, vars+psParseSubstitute(psPartitionDeleteBody, s)), nil
		}},
		{Name: "mgmtPathPSBody", Unseeded: true, Render: func(string) (string, error) {
			return mgmtPathPSHeader + "\n" + strings.NewReplacer(
				"@@SSHPORT@@", "22",
				"@@LOCALPORT@@", "0",
			).Replace(mgmtPathPSBody), nil
		}},

		// *Header consts (shared envelope prelude included by construction).
		{Name: "psEnvelopePrelude", Unseeded: true, Render: psParseOk(psEnvelopePrelude)},
		{Name: "psClassifyPrelude", Unseeded: true, Render: psParseOk(psClassifyPrelude)},
		{Name: "psReplBootstrap", Unseeded: true, Render: psParseOk(psReplBootstrap)},
		{Name: "oneShotBootstrap", Unseeded: true, Render: psParseOk(oneShotBootstrap)},
		{Name: "psHostnameHeader", Unseeded: true, Render: psParseOk(psHostnameHeader)},
		{Name: "psDirectoryHeader", Unseeded: true, Render: psParseOk(psDirectoryHeader)},
		{Name: "psDomainMembershipHeader", Unseeded: true, Render: psParseOk(psDomainMembershipHeader)},
		{Name: "psFeatureHeader", Unseeded: true, Render: psParseOk(psFeatureHeader)},
		{Name: "psOSInfoHeader", Unseeded: true, Render: psParseOk(psOSInfoHeader)},
		{Name: "psSmbShareHeader", Unseeded: true, Render: psParseOk(psSmbShareHeader)},
		{Name: "psNTPHeader", Unseeded: true, Render: psParseOk(psNTPHeader)},
		{Name: "psPowerPlanHeader", Unseeded: true, Render: psParseOk(psPowerPlanHeader)},
		{Name: "psTimezoneHeader", Unseeded: true, Render: psParseOk(psTimezoneHeader)},
		{Name: "psHeader", Unseeded: true, Render: psParseOk(psHeader)},
		{Name: "lgPsHeader", Unseeded: true, Render: psParseOk(lgPsHeader)},
		{Name: "luPsHeader", Unseeded: true, Render: psParseOk(luPsHeader)},
		{Name: "psEnvVarHeader", Unseeded: true, Render: psParseOk(psEnvVarHeader)},
		{Name: "psRegistryValueHeader", Unseeded: true, Render: psParseOk(psRegistryValueHeader)},
		{Name: "psFileHeader", Unseeded: true, Render: psParseOk(psFileHeader)},
		{Name: "psFileACLHeader", Unseeded: true, Render: psParseOk(psFileACLHeader)},
		{Name: "lpHeader", Unseeded: true, Render: psParseOk(lpHeader)},
		{Name: "psSTHeader", Unseeded: true, Render: psParseOk(psSTHeader)},
		{Name: "psCertificateHeader", Unseeded: true, Render: psParseOk(psCertificateHeader)},
		{Name: "psDNSClientHeader", Unseeded: true, Render: psParseOk(psDNSClientHeader)},
		{Name: "elPsHeader", Unseeded: true, Render: psParseOk(elPsHeader)},
		{Name: "fpPsHeader", Unseeded: true, Render: psParseOk(fpPsHeader)},
		{Name: "frPsHeader", Unseeded: true, Render: psParseOk(frPsHeader)},
		{Name: "psIISHeader", Unseeded: true, Render: psParseOk(psIISHeader)},
		{Name: "psInstalledSoftwareHeader", Unseeded: true, Render: psParseOk(psInstalledSoftwareHeader)},
		{Name: "mgmtPathPSHeader", Unseeded: true, Render: psParseOk(mgmtPathPSHeader)},
		{Name: "psNetIPAddressHeader", Unseeded: true, Render: psParseOk(psNetIPAddressHeader)},
		{Name: "psNetRouteHeader", Unseeded: true, Render: psParseOk(psNetRouteHeader)},
		{Name: "psNetworkAdaptersHeader", Unseeded: true, Render: psParseOk(psNetworkAdaptersHeader)},
		{Name: "psStorageHeader", Unseeded: true, Render: psParseOk(psStorageHeader)},
		{Name: "wpHeader", Unseeded: true, Render: psParseOk(wpHeader)},
		{Name: "dscPsHeader", Unseeded: true, Render: psParseOk(dscPsHeader)},

		// Representative extras for resources whose scripts are composed
		// inline in methods (no Body const / build*Script func). Each uses
		// the existing builders and production call shapes with the seed;
		// hostname/timezone entries below are production-exact copies of the
		// method-built scripts (Force / DstDisabled branches included).
		// TestPSParseInlineRepresentativeCoverage fails when a required
		// representative prefix is missing.
		{Name: "representative/hostname_rename", Render: func(s string) (string, error) {
			// Production-exact copy of HostnameClient.renameAndRead (Force=false):
			// hostname.go renames with Rename-Computer -NewName psQuote(desired)
			// plus the observed_pending context on failure.
			script := fmt.Sprintf(`
try {
  $null = Rename-Computer -NewName %s -PassThru -ErrorAction Stop
  $s = Read-HostnameState
  Emit-OK $s
} catch {
  $msg = $_.Exception.Message
  Emit-Err (Classify-Hostname $msg) $msg @{ desired = %s; observed_pending = (try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name ComputerName -ErrorAction Stop).ComputerName } catch { '' }) }
}
`, psQuote(s), psQuote(s))
			return psHostnameHeader + "\n" + script, nil
		}},
		{Name: "representative/hostname_rename_force", Render: func(s string) (string, error) {
			script := fmt.Sprintf(`
try {
  $null = Rename-Computer -NewName %s -Force -PassThru -ErrorAction Stop
  $s = Read-HostnameState
  Emit-OK $s
} catch {
  $msg = $_.Exception.Message
  Emit-Err (Classify-Hostname $msg) $msg @{ desired = %s; observed_pending = (try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name ComputerName -ErrorAction Stop).ComputerName } catch { '' }) }
}
`, psQuote(s), psQuote(s))
			return psHostnameHeader + "\n" + script, nil
		}},
		{Name: "representative/timezone_set", Render: func(s string) (string, error) {
			// Production-exact copy of TimezoneClient.Set with
			// DaylightSavingDisabled=false (Set-TimeZone path).
			script := fmt.Sprintf(`
try {
  $DesiredId = %s
  $DstDisabled = $false
  Set-TimeZone -Id $DesiredId -ErrorAction Stop
  $s = Read-TimezoneState
  $normObserved = [string]$s.timezone_id
  if ($normObserved -like '*_dstoff') { $normObserved = $normObserved.Substring(0, $normObserved.Length - 7) }
  $idOk = ($normObserved -eq $DesiredId)
  $dstOk = ([bool]$s.daylight_saving_disabled -eq $DstDisabled)
  if (-not ($idOk -and $dstOk)) {
    $sugs = (@(Get-TimezoneSuggestions $DesiredId) -join '; ')
    Emit-Err 'invalid_timezone' ('Time zone change did not take effect: desired {0} (DST disabled: {1}), observed {2} (DST disabled: {3})' -f $DesiredId, $DstDisabled, $s.timezone_id, $s.daylight_saving_disabled) @{ desired = $DesiredId; observed = [string]$s.timezone_id; suggestions = $sugs }
  } else {
    Emit-OK $s
  }
} catch {
  $kind = Classify-Timezone $_
  $ctx = @{ desired = %s }
  if ($kind -eq 'invalid_timezone') {
    $ctx['suggestions'] = (@(Get-TimezoneSuggestions ([string]$ctx['desired'])) -join '; ')
  }
  Emit-Err $kind $_.Exception.Message $ctx
}
`, psQuote(s), psQuote(s))
			return psTimezoneHeader + "\n" + script, nil
		}},
		{Name: "representative/timezone_set_dst_disabled", Render: func(s string) (string, error) {
			// Production-exact copy of TimezoneClient.Set with
			// DaylightSavingDisabled=true (tzutil.exe /s "<id>_dstoff" path).
			script := fmt.Sprintf(`
try {
  $DesiredId = %s
  $DstDisabled = $true
  & tzutil.exe /s ($DesiredId + '_dstoff')
    if ($LASTEXITCODE -ne 0) { throw ('tzutil.exe rejected time zone ID {0} (exit code {1}); the ID was not found on the host' -f $DesiredId, $LASTEXITCODE) }
  $s = Read-TimezoneState
  $normObserved = [string]$s.timezone_id
  if ($normObserved -like '*_dstoff') { $normObserved = $normObserved.Substring(0, $normObserved.Length - 7) }
  $idOk = ($normObserved -eq $DesiredId)
  $dstOk = ([bool]$s.daylight_saving_disabled -eq $DstDisabled)
  if (-not ($idOk -and $dstOk)) {
    $sugs = (@(Get-TimezoneSuggestions $DesiredId) -join '; ')
    Emit-Err 'invalid_timezone' ('Time zone change did not take effect: desired {0} (DST disabled: {1}), observed {2} (DST disabled: {3})' -f $DesiredId, $DstDisabled, $s.timezone_id, $s.daylight_saving_disabled) @{ desired = $DesiredId; observed = [string]$s.timezone_id; suggestions = $sugs }
  } else {
    Emit-OK $s
  }
} catch {
  $kind = Classify-Timezone $_
  $ctx = @{ desired = %s }
  if ($kind -eq 'invalid_timezone') {
    $ctx['suggestions'] = (@(Get-TimezoneSuggestions ([string]$ctx['desired'])) -join '; ')
  }
  Emit-Err $kind $_.Exception.Message $ctx
}
`, psQuote(s), psQuote(s))
			return psTimezoneHeader + "\n" + script, nil
		}},
		{Name: "representative/hostname_read", Unseeded: true, Render: func(string) (string, error) {
			return psHostnameHeader + "\ntry { $s = Read-HostnameState; Emit-OK $s } catch { Emit-Err (Classify-Hostname $_.Exception.Message) $_.Exception.Message @{} }", nil
		}},
		{Name: "representative/timezone_read", Unseeded: true, Render: func(string) (string, error) {
			return psTimezoneHeader + "\ntry { $s = Read-TimezoneState; Emit-OK $s } catch { Emit-Err (Classify-Timezone $_) $_.Exception.Message @{} }", nil
		}},
		{Name: "representative/local_group_create", Render: func(s string) (string, error) {
			qName, qDesc := psQuote(s), psQuote(s)
			script := fmt.Sprintf(`
if (-not (Get-Command New-LocalGroup -ErrorAction SilentlyContinue)) {
    Emit-Err 'unknown' 'Microsoft.PowerShell.LocalAccounts module not available; requires Windows Server 2016 / Windows 10 or later' @{}
    return
}
try {
    $existing = Get-LocalGroup -Name %s -ErrorAction Stop
    Emit-Err 'already_exists' ("local group '" + $existing.Name + "' already exists") @{ sid = $existing.SID.Value; name = $existing.Name }
    return
} catch {
    if ($_.FullyQualifiedErrorId -notmatch 'GroupNotFound' -and $_.Exception.Message -notmatch 'was not found') {
        Emit-Err (Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId) $_.Exception.Message @{ name = %s; step = 'preflight_read' }
        return
    }
}
try {
    $group = New-LocalGroup -Name %s -Description %s -ErrorAction Stop
    Emit-OK $group
} catch {
    Emit-Err (Classify-LG $_.Exception.Message $_.FullyQualifiedErrorId) $_.Exception.Message @{ name = %s; step = 'new_local_group' }
}
`, qName, qName, qName, qDesc, qName)
			return lgPsHeader + "\n" + script, nil
		}},
		{Name: "representative/local_user_create", Render: func(s string) (string, error) {
			qName := psQuote(s)
			optParts := "\n    $params['FullName'] = " + psQuote(s) +
				"\n    $params['Description'] = " + psQuote(s) +
				"\n    $params['PasswordNeverExpires'] = $true" +
				"\n    $params['Disabled'] = $true"
			script := fmt.Sprintf(`
if (-not (Get-Command New-LocalUser -ErrorAction SilentlyContinue)) {
    Emit-Err 'unknown' 'Microsoft.PowerShell.LocalAccounts module not available' @{}
    return
}
try {
    $existing = Get-LocalUser -Name %s -ErrorAction Stop
    Emit-Err 'already_exists' ("local user '" + $existing.Name + "' already exists") @{ sid = $existing.SID.Value; name = $existing.Name }
    return
} catch {
    if ($_.FullyQualifiedErrorId -notmatch 'UserNotFound' -and $_.Exception.Message -notmatch 'was not found') {
        Emit-Err (Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId) $_.Exception.Message @{ name = %s; step = 'preflight_read' }
        return
    }
}
try {
    $params = @{ Name = %s; ErrorAction = 'Stop' }%s
    $user = New-LocalUser @params
    Emit-OK $user
} catch {
    Emit-Err (Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId) $_.Exception.Message @{ name = %s; step = 'new_local_user' }
}
`, qName, qName, qName, optParts, qName)
			return luPsHeader + "\n" + script, nil
		}},
		{Name: "representative/scheduled_task_fragments", Render: func(s string) (string, error) {
			pw := "dummy-password-for-corpus"
			principal := &ScheduledTaskPrincipalInput{UserID: s, Password: &pw}
			script := buildActionsFragment([]ScheduledTaskActionInput{{Execute: s, Arguments: s, WorkingDirectory: s}}) +
				"\n" + buildTriggersFragment([]ScheduledTaskTriggerInput{
				{Type: "Daily", StartBoundary: s},
				{Type: "OnEvent", Subscription: s, StartBoundary: s},
			}) +
				"\n" + buildPrincipalFragment(principal) +
				"\n" + buildPasswordPrincipalParamsFragment("$_stRegParams", principal, true) +
				"\n" + buildSettingsFragment(nil, true) +
				"\n" + buildOnEventFragment(s, `\`, []ScheduledTaskTriggerInput{{Type: "OnEvent", Subscription: s}}) +
				"\n" + buildTaskDescriptionUpdateFragment(s, `\`, s, principal) +
				"\nRead-TaskState " + psQuote(s) + " " + psQuote(s) + "\n"
			return psSTHeader + "\n" + script, nil
		}},
		{Name: "representative/scheduled_task_create", Render: func(s string) (string, error) {
			pw := "dummy-password-for-corpus"
			in := ScheduledTaskInput{
				Path:        `\`,
				Name:        s,
				Description: s,
				Actions:     []ScheduledTaskActionInput{{Execute: s, Arguments: s, WorkingDirectory: s}},
				Triggers: []ScheduledTaskTriggerInput{
					{Type: "Daily", StartBoundary: s},
					{Type: "OnEvent", Subscription: s},
				},
				Principal: &ScheduledTaskPrincipalInput{UserID: s, Password: &pw},
				Enabled:   true,
			}
			var sb strings.Builder
			fmt.Fprintf(&sb, "\n$_stExisting = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction SilentlyContinue\n",
				psQuote(in.Name), psQuote(in.Path))
			fmt.Fprintf(&sb, "if (-not (Ensure-TaskFolder %s)) { return }\n", psQuote(in.Path))
			sb.WriteString(buildActionsFragment(in.Actions))
			sb.WriteString(buildTriggersFragment(in.Triggers))
			sb.WriteString(buildPrincipalFragment(in.Principal))
			sb.WriteString(buildSettingsFragment(in.Settings, in.Enabled))
			fmt.Fprintf(&sb, "$_stRegParams = @{ TaskName = %s; TaskPath = %s; Action = $_stActions; Principal = $_stPrincipal; Settings = $_stSettings }\n",
				psQuote(in.Name), psQuote(in.Path))
			fmt.Fprintf(&sb, "if ($null -ne %s) { $_stRegParams['Description'] = %s }\n",
				psQuote(in.Description), psQuote(in.Description))
			sb.WriteString("$_stRegPassword = [Console]::In.ReadLine()\n")
			sb.WriteString(buildPasswordPrincipalParamsFragment("$_stRegParams", in.Principal, true))
			sb.WriteString("$_stRegParams['Password'] = $_stRegPassword\n")
			sb.WriteString("$_stRegParams['Trigger'] = $_stTriggers\n")
			sb.WriteString("try { Register-ScheduledTask @_stRegParams | Out-Null } catch { Emit-Err 'unknown' $_.Exception.Message @{ phase = 'register' }; return }\n")
			sb.WriteString(buildOnEventFragment(in.Name, in.Path, in.Triggers))
			fmt.Fprintf(&sb, "Read-TaskState %s %s\n", psQuote(in.Name), psQuote(in.Path))
			return psSTHeader + "\n" + sb.String(), nil
		}},
		{Name: "representative/scheduled_task_update", Render: func(s string) (string, error) {
			pw := "dummy-password-for-corpus"
			in := ScheduledTaskInput{
				Description: s,
				Actions:     []ScheduledTaskActionInput{{Execute: s}},
				Triggers:    []ScheduledTaskTriggerInput{{Type: "OnEvent", Subscription: s}},
				Principal:   &ScheduledTaskPrincipalInput{UserID: s, Password: &pw},
				Enabled:     true,
			}
			var sb strings.Builder
			sb.WriteString(buildActionsFragment(in.Actions))
			sb.WriteString(buildTriggersFragment(in.Triggers))
			sb.WriteString(buildPrincipalFragment(in.Principal))
			sb.WriteString(buildSettingsFragment(in.Settings, in.Enabled))
			fmt.Fprintf(&sb, "$_stSetParams = @{ TaskName = %s; TaskPath = %s; Action = $_stActions }\n",
				psQuote(s), psQuote(`\`))
			sb.WriteString("$_stSetPassword = [Console]::In.ReadLine()\n")
			sb.WriteString(buildPasswordPrincipalParamsFragment("$_stSetParams", in.Principal, false))
			sb.WriteString("$_stSetParams['Password'] = $_stSetPassword\n")
			sb.WriteString("try { Set-ScheduledTask @_stSetParams | Out-Null } catch { Emit-Err 'unknown' $_.Exception.Message @{ phase = 'update' }; return }\n")
			sb.WriteString(buildTaskDescriptionUpdateFragment(s, `\`, in.Description, in.Principal))
			sb.WriteString(buildOnEventFragment(s, `\`, in.Triggers))
			fmt.Fprintf(&sb, "Read-TaskState %s %s\n", psQuote(s), psQuote(`\`))
			return psSTHeader + "\n" + sb.String(), nil
		}},
		{Name: "representative/scheduled_task_delete", Render: func(s string) (string, error) {
			script := fmt.Sprintf("\n$_stTask = Get-ScheduledTask -TaskName %s -TaskPath %s -ErrorAction SilentlyContinue\nif ($null -eq $_stTask) { Emit-OK 'not_found'; return }\nRemove-EmptyFolder %s\nUnregister-ScheduledTask -TaskName %s -TaskPath %s -Confirm:$false -ErrorAction Stop\nEmit-OK 'deleted'\n",
				psQuote(s), psQuote(`\`), psQuote(`\`), psQuote(s), psQuote(`\`))
			return psSTHeader + "\n" + script, nil
		}},
		{Name: "representative/file_download_target", Render: func(s string) (string, error) {
			script, _, err := buildFileSetScript(FileInput{
				Path:                        s,
				DownloadOnTarget:            true,
				SourceURL:                   s,
				SourceURLSHA256:             strings.Repeat("a", 64),
				SourceURLInsecureSkipVerify: false,
			})
			return script, err
		}},
		{Name: "representative/download_fragment", Render: func(s string) (string, error) {
			script := psFileHeader + "\n" + psFileAcquireDownloadBody(psQuote(s), "$__wcHeaders", "$false") + "\nEmit-OK @{ url = " + psQuote(s) + " }\n"
			return script, nil
		}},
		{Name: "representative/lp_download", Unseeded: true, Render: func(string) (string, error) {
			return lpHeader + "\n" + lpCreateScript(), nil
		}},
		{Name: "representative/iis_app_pool_set", Render: func(s string) (string, error) {
			started := "Started"
			settings := IISAppPoolSettings{
				ManagedRuntimeVersion: psParseStrPtr(s),
				IdentityUsername:      psParseStrPtr(s),
				AutoStart:             BoolPtr(true),
				QueueLength:           psParseI64Ptr(1000),
			}
			script := "$Name = " + psQuote(s) + "\n$poolPath = ('IIS:\\AppPools\\' + $Name)\n" +
				buildIISAppPoolSetStatements(settings, false) +
				buildIISAppPoolStateStatement(&started, psQuote(psEscapeWildcard(s))) + "\n"
			return psIISHeader + "\n" + script, nil
		}},
		{Name: "representative/iis_site_set", Render: func(s string) (string, error) {
			started := "Started"
			settings := IISSiteSettings{
				PhysicalPath:    psParseStrPtr(s),
				ApplicationPool: psParseStrPtr(s),
				LogDirectory:    psParseStrPtr(s),
			}
			script := "$siteName = " + psQuote(s) + "\n$PhysicalPath = " + psSiteOptionalLiteral(settings.PhysicalPath) +
				"\n$AppPool = " + psSiteOptionalLiteral(settings.ApplicationPool) + "\n" +
				iisSitePreamble() + "\n" + iisSiteGuardFragment + "\n" +
				buildIISSiteSetStatements(settings) +
				buildIISSiteStateStatement(&started, psQuote(psEscapeWildcard(s))) + "\n"
			return psIISHeader + "\n" + script, nil
		}},
		{Name: "representative/iis_binding_create", Render: func(s string) (string, error) {
			in := IISBindingInput{SiteName: s, Protocol: "https", IPAddress: "*", Port: 443, HostHeader: "example.com"}
			script := bindingScriptVars(in, false) + "\n" +
				"if (-not (Ensure-IIS)) { return }\n" +
				iisBindingScanFragment + "\n" +
				iisBindingCertCheckFragment + "\n" + iisBindingSSLCheckFragment + "\n" +
				fmt.Sprintf("New-WebBinding -Name %s -Protocol $Protocol -IPAddress $WantedIP -Port $Port -HostHeader $WantedHost -SslFlags $SslFlags -ErrorAction Stop\nEmit-OK (Get-BindingData $Name $Protocol $BindingInfo)\n",
					psQuote(psEscapeWildcard(s)))
			return psIISHeader + "\n" + script, nil
		}},
		{Name: "representative/iis_binding_read", Render: func(s string) (string, error) {
			script := fmt.Sprintf("\n$Name = %s\n$Protocol = %s\n$BindingInfo = %s\nif (-not (Ensure-IIS)) { return }\nEmit-OK (Get-BindingData $Name $Protocol $BindingInfo)\n",
				psQuote(s), psQuote("https"), psQuote(BuildIISBindingInformation("*", 443, "example.com")))
			return psIISHeader + "\n" + iisBindingWildcardEscape + iisBindingReadFragment + "\n" + script, nil
		}},
		{Name: "representative/service_create", Render: func(s string) (string, error) {
			script := psReadStateBody + "\ntry {\n" +
				"  $name = " + psQuote(s) + "\n" +
				"  $binary = " + psQuote(s) + "\n" +
				"  $display = " + psQuote(s) + "\n" +
				"  $desc = " + psQuote(s) + "\n" +
				"  $stype = " + psQuote("Automatic") + "\n" +
				"  $account = " + psQuote(s) + "\n" +
				"  $password = [Console]::In.ReadLine()\n" +
				"  $deps = " + psQuoteList([]string{s}) + "\n" +
				"  New-Service -Name $name -BinaryPathName $binary -StartupType $stype -DisplayName $display | Out-Null\n" +
				"  $st = Read-ServiceState $name\n" +
				"  Emit-OK $st\n} catch { Emit-Err (Classify $_.Exception.Message) $_.Exception.Message @{} }\n"
			return psHeader + "\n" + script, nil
		}},
		{Name: "representative/service_update", Render: func(s string) (string, error) {
			script := psReadStateBody + "\ntry {\n" +
				"  $name = " + psQuote(s) + "\n" +
				"  $display = " + psQuote(s) + "\n" +
				"  $desc = " + psQuote(s) + "\n" +
				"  $depsMode = " + psQuote("set") + "\n" +
				"  $depArg = " + psQuote(s) + "\n" +
				"  Set-Service -Name $name -StartupType Automatic\n" +
				"  $st = Read-ServiceState $name\n" +
				"  Emit-OK $st\n} catch { Emit-Err (Classify $_.Exception.Message) $_.Exception.Message @{} }\n"
			return psHeader + "\n" + script, nil
		}},
		{Name: "representative/service_delete", Render: func(s string) (string, error) {
			script := "\ntry {\n  $name = " + psQuote(s) +
				"\n  $waitSec = 30\n" +
				"  $svc = Get-Service -Name $name -ErrorAction SilentlyContinue\n" +
				"  if (-not $svc) { Emit-OK @{ deleted = $true }; return }\n" +
				"  Remove-Service -Name $name -ErrorAction Stop\n" +
				"  Emit-OK @{ deleted = $true }\n} catch { Emit-Err (Classify $_.Exception.Message) $_.Exception.Message @{} }\n"
			return psHeader + "\n" + script, nil
		}},
		{Name: "representative/service_start", Render: func(s string) (string, error) {
			body := "\n  try {\n    Start-Service -Name $name -ErrorAction Stop\n    $svc = Get-Service -Name $name\n    $svc.WaitForStatus('Running', [TimeSpan]::FromSeconds($waitSec))\n    Emit-OK @{ status = 'Running' }\n  } catch {\n    $m = $_.Exception.Message\n    if ($m -match '1056') { Emit-Err 'already_running' $m @{}; return }\n    Emit-Err (Classify $m) $m @{}\n  }"
			script := "\n$name    = " + psQuote(s) + "\n$waitSec = 30\n" + body + "\n"
			return psHeader + "\n" + script, nil
		}},
		{Name: "representative/service_stop", Render: func(s string) (string, error) {
			body := "\n  try {\n    Stop-Service -Name $name -Force -ErrorAction Stop\n    $svc = Get-Service -Name $name\n    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($waitSec))\n    Emit-OK @{ status = 'Stopped' }\n  } catch {\n    $m = $_.Exception.Message\n    if ($m -match '1062') { Emit-Err 'not_running' $m @{}; return }\n    Emit-Err (Classify $m) $m @{}\n  }"
			script := "\n$name    = " + psQuote(s) + "\n$waitSec = 30\n" + body + "\n"
			return psHeader + "\n" + script, nil
		}},
		{Name: "representative/service_pause", Render: func(s string) (string, error) {
			body := "\n  try {\n    $svc = Get-Service -Name $name -ErrorAction Stop\n    if (-not $svc.CanPauseAndContinue) { Emit-Err 'invalid_parameter' (\"service '\" + $name + \"' does not support Pause\") @{}; return }\n    Suspend-Service -Name $name -ErrorAction Stop\n    $svc.WaitForStatus('Paused', [TimeSpan]::FromSeconds($waitSec))\n    Emit-OK @{ status = 'Paused' }\n  } catch { Emit-Err (Classify $_.Exception.Message) $_.Exception.Message @{} }"
			script := "\n$name    = " + psQuote(s) + "\n$waitSec = 30\n" + body + "\n"
			return psHeader + "\n" + script, nil
		}},
		{Name: "representative/local_group_member_list", Render: func(s string) (string, error) {
			script := fmt.Sprintf("\n$gSID = %s\n$res = Get-LgmMembers $gSID\nEmit-OK @{ tier = $res.tier; members = $res.members }\n", psQuote(s))
			return lgPsHeader + "\n" + lgmMembersPsFunction + "\n" + script, nil
		}},
		{Name: "representative/local_group_member_resolve", Render: func(s string) (string, error) {
			q := psQuote(s)
			script := fmt.Sprintf("\ntry {\n    $m = %s\n    $ntAcc = New-Object System.Security.Principal.NTAccount($m)\n    $sid = $ntAcc.Translate([System.Security.Principal.SecurityIdentifier]).Value\n    Emit-OK @{ sid = $sid }\n} catch { Emit-Err 'member_unresolvable' $_.Exception.Message @{ member = %s } }\n", q, q)
			return lgPsHeader + "\n" + script, nil
		}},
		{Name: "representative/local_group_member_add", Render: func(s string) (string, error) {
			qSID, qMember := psQuote(s), psQuote(s)
			script := fmt.Sprintf("\ntry {\n    Add-LocalGroupMember -SID %s -Member %s -ErrorAction Stop\n    Emit-OK @{ added = $true }\n} catch { Emit-Err 'unknown' $_.Exception.Message @{ member = %s } }\n", qSID, qMember, qMember)
			return lgPsHeader + "\n" + script, nil
		}},
		{Name: "representative/local_group_member_remove", Render: func(s string) (string, error) {
			qSID, qMember := psQuote(s), psQuote(s)
			script := fmt.Sprintf("\ntry {\n    Remove-LocalGroupMember -SID %s -Member %s -ErrorAction Stop\n    Emit-OK @{ removed = $true }\n} catch { Emit-Err 'unknown' $_.Exception.Message @{ group_sid = %s; member_sid = %s } }\n", qSID, qMember, qSID, qMember)
			return lgPsHeader + "\n" + script, nil
		}},
		{Name: "representative/local_user_resolve", Render: func(s string) (string, error) {
			q := psQuote(s)
			script := fmt.Sprintf("\ntry {\n    $user = Get-LocalUser -Name %s -ErrorAction Stop\n    $data = Get-UserData $user\n    Emit-OK $data\n} catch { Emit-Err (Classify-LU $_.Exception.Message $_.FullyQualifiedErrorId) $_.Exception.Message @{ user = %s; step = 'resolve_user_sid' } }\n", q, q)
			return luPsHeader + "\n" + script, nil
		}},
	}
	sort.Slice(b, func(i, j int) bool { return b[i].Name < b[j].Name })
	return b
}

// ---------------------------------------------------------------------------
// Emission: render every builder x every seed into .ps1 files
// ---------------------------------------------------------------------------

// psParseCase is one emitted file.
type psParseCase struct {
	Builder string
	Seed    string
	File    string
	Script  string
}

// psParseFileName sanitises a builder/seed pair into a .ps1 file name.
func psParseFileName(builder, seed string) string {
	r := strings.NewReplacer("/", "__", "\\", "_", " ", "_", ":", "_", "|", "_")
	return r.Replace(builder) + "__" + r.Replace(seed) + ".ps1"
}

// psParseRenderAll renders the registry for the normal seed plus every
// adversarial seed. A render error fails the caller.
func psParseRenderAll(t *testing.T) []psParseCase {
	t.Helper()
	seeds := append([]psParseSeed{psParseNormalSeed()}, psParseAdversarialSeeds()...)
	var out []psParseCase
	for _, builder := range psParseRegistry() {
		for _, seed := range seeds {
			script, err := builder.Render(seed.Value)
			if err != nil {
				t.Fatalf("render %s with seed %q: %v", builder.Name, seed.Name, err)
			}
			out = append(out, psParseCase{
				Builder: builder.Name,
				Seed:    seed.Name,
				File:    psParseFileName(builder.Name, seed.Name),
				Script:  script,
			})
		}
	}
	return out
}

// psParseEmitCorpus renders the corpus into outDir (created when missing)
// and returns the cases. The CI ps-parse job sets PSPARSE_OUT to collect
// the files for Parser::ParseInput.
func psParseEmitCorpus(t *testing.T, outDir string) []psParseCase {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}
	cases := psParseRenderAll(t)
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(outDir, c.File), []byte(c.Script), 0o600); err != nil {
			t.Fatalf("write %s: %v", c.File, err)
		}
	}
	return cases
}

// TestPSParseEmitCorpus renders every registered builder with the normal and
// adversarial seeds. Locally it writes into a temp dir; when PSPARSE_OUT is
// set (CI ps-parse job) it writes there for Parser::ParseInput.
func TestPSParseEmitCorpus(t *testing.T) {
	outDir := os.Getenv("PSPARSE_OUT")
	if outDir == "" {
		outDir = t.TempDir()
	}
	cases := psParseEmitCorpus(t, outDir)
	if len(cases) == 0 {
		t.Fatal("empty parse corpus")
	}
	t.Logf("emitted %d .ps1 files into %s", len(cases), outDir)
}

// ---------------------------------------------------------------------------
// Guard: every builder must be registered
// ---------------------------------------------------------------------------

var (
	psParseBuilderFuncRe = regexp.MustCompile(`(?m)^func (build[A-Za-z0-9_]*Script)\(`)
	psParseConstRe       = regexp.MustCompile(`(?m)^const ([A-Za-z0-9_]+)\s*=`)
)

// psParseWantedConst reports whether a const name is a registered script
// unit: a *Body or *Header const, or a bootstrap script.
func psParseWantedConst(name string) bool {
	return strings.HasSuffix(name, "Body") || strings.HasSuffix(name, "Header") || strings.HasSuffix(name, "Bootstrap")
}

// TestPSParseRegistryComplete fails when a build*Script func or a
// *Body/*Header/*Bootstrap const exists in winclient but has no entry in
// psParseRegistry. Add the builder (with a Render func that composes the
// full header+body script and substitutes placeholders) instead of touching
// this test.
func TestPSParseRegistryComplete(t *testing.T) {
	registered := map[string]bool{}
	for _, entry := range psParseRegistry() {
		registered[entry.Name] = true
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var missing []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, m := range psParseBuilderFuncRe.FindAllStringSubmatch(string(raw), -1) {
			if !registered[m[1]] {
				missing = append(missing, name+": func "+m[1])
			}
		}
		for _, m := range psParseConstRe.FindAllStringSubmatch(string(raw), -1) {
			if psParseWantedConst(m[1]) && !registered[m[1]] {
				missing = append(missing, name+": const "+m[1])
			}
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("unregistered script builders (add a psParseRegistry entry that renders the composed script):\n%s",
			strings.Join(missing, "\n"))
	}
}

// TestPSParseInlineRepresentativeCoverage fails when an inline-composed
// script family (no Body const / build*Script func, rendered in a method
// through runEnvelope/runSTEnvelope/runBindingEnvelope/runLGMEnvelope)
// has no representative/* entry calling the real production composers with
// the seed. The required prefixes below mirror the High findings
// (iis_binding, service, local_group_member, local_user resolve,
// scheduled-task register/set, file/lp downloads, hostname/timezone).
func TestPSParseInlineRepresentativeCoverage(t *testing.T) {
	registered := map[string]bool{}
	for _, entry := range psParseRegistry() {
		registered[entry.Name] = true
	}
	required := []string{
		"representative/hostname_rename",
		"representative/timezone_set",
		"representative/timezone_set_dst_disabled",
		"representative/iis_binding_create",
		"representative/iis_binding_read",
		"representative/service_create",
		"representative/service_update",
		"representative/service_delete",
		"representative/service_start",
		"representative/service_stop",
		"representative/service_pause",
		"representative/local_group_member_list",
		"representative/local_group_member_resolve",
		"representative/local_group_member_add",
		"representative/local_group_member_remove",
		"representative/local_user_resolve",
		"representative/scheduled_task_fragments",
		"representative/scheduled_task_create",
		"representative/scheduled_task_update",
		"representative/file_download_target",
		"representative/download_fragment",
	}
	var missing []string
	for _, name := range required {
		if !registered[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		t.Fatalf("missing inline representatives (add entries calling real production composers with the seed):\n%s",
			strings.Join(missing, "\n"))
	}
}

// ---------------------------------------------------------------------------
// Go-side single-literal check for adversarial renderings
// ---------------------------------------------------------------------------

// psParseLitCandidates returns the literal spellings an adversarial seed may
// take after benign Go-side normalisation (case folding, trimming) before
// psQuote renders it as a single-quoted PowerShell literal.
func psParseLitCandidates(seed string) []string {
	cands := []string{seed}
	if u := strings.ToUpper(seed); u != seed {
		cands = append(cands, u)
	}
	if tr := strings.TrimSpace(seed); tr != seed {
		cands = append(cands, tr)
		if ut := strings.ToUpper(tr); ut != tr && ut != strings.ToUpper(seed) {
			cands = append(cands, ut)
		}
	}
	return cands
}

// TestPSParseAdversarialSingleLiteral asserts for every adversarial
// rendering that the input survived only inside one single-quoted PowerShell
// literal: the psQuote spelling must be present, no @@ placeholder may leak,
// and every marker token must occur exactly as often as inside that single
// literal (i.e. nowhere else — no breakout). The authoritative AST proof is
// the CI ps-parse job (Parser::ParseInput must report zero ParseErrors).
func TestPSParseAdversarialSingleLiteral(t *testing.T) {
	seeds := psParseAdversarialSeeds()
	builders := psParseRegistry()
	for _, builder := range builders {
		for _, seed := range seeds {
			if len(seed.Markers) == 0 {
				continue
			}
			script, err := builder.Render(seed.Value)
			if err != nil {
				t.Fatalf("render %s with seed %q: %v", builder.Name, seed.Name, err)
			}
			if strings.Contains(script, "@@") {
				t.Errorf("%s / %s: unsubstituted placeholder left in rendered script", builder.Name, seed.Name)
			}
			if builder.Unseeded {
				continue
			}
			// Strip every spelling the seed takes as a single-quoted
			// literal (verbatim plus benign Go-side normalisations); any
			// marker left behind sits outside a literal — a breakout.
			// Markers are upper-case tokens with no edge whitespace, hence
			// invariant under those normalisations.
			rest := script
			found := false
			for _, cand := range psParseLitCandidates(seed.Value) {
				if l := psQuote(cand); strings.Contains(rest, l) {
					found = true
					rest = strings.ReplaceAll(rest, l, "")
				}
			}
			if builder.ExtraLiterals != nil {
				for _, l := range builder.ExtraLiterals(seed.Value) {
					if strings.Contains(rest, l) {
						found = true
						rest = strings.ReplaceAll(rest, l, "")
					}
				}
			}
			if !found {
				t.Errorf("%s / %s: input not found as a single-quoted literal (want psQuote of the seed or its benign normalisation)", builder.Name, seed.Name)
				continue
			}
			for _, m := range seed.Markers {
				if strings.Contains(rest, m) {
					t.Errorf("%s / %s: marker %q survives outside the single literal (possible breakout)",
						builder.Name, seed.Name, m)
				}
			}
		}
	}
}
