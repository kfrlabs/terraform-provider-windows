// Safe PowerShell single-quoted string literals.
//
// psQuote renders a Go string as a single-quoted PowerShell string literal.
// No PowerShell expansion occurs inside single quotes, which prevents $var,
// backtick, and subexpression injection — provided every character the
// PowerShell tokenizer treats as a single quote is escaped.
//
// The tokenizer treats five characters as single-quote delimiters (see
// System.Management.Automation.Language.CharExtensions.IsSingleQuote):
//
//	U+0027 APOSTROPHE          '
//	U+2018 LEFT SINGLE QUOTATION MARK  ‘
//	U+2019 RIGHT SINGLE QUOTATION MARK ’
//	U+201A SINGLE LOW-9 QUOTATION MARK ‚
//	U+201B SINGLE HIGH-REVERSED-9 QUOTATION MARK ‛
//
// .NET's CodeGeneration.EscapeSingleQuotedStringContent escapes all five by
// doubling; psQuote mirrors that rule. Escaping only U+0027 leaves an
// injection vector: since scripts are transported as exact UTF-16LE, a value
// such as "x’; <code>; ’" terminates the literal and executes arbitrary code
// as the SSH user (typically an administrator). Smart quotes also arrive
// accidentally via copy-paste from documents, producing confusing parse
// errors when left unescaped.
//
// Invariant: every user-supplied string reaching a PowerShell script must go
// through psQuote (or psQuoteList). Secrets must additionally avoid the
// script body entirely and travel on stdin via RunPowerShellWithInput.
package winclient

import "strings"

// psSingleQuoteReplacer doubles each character PowerShell treats as a single
// quote. A single shared Replacer performs the substitution in one pass.
var psSingleQuoteReplacer = strings.NewReplacer(
	"'", "''", // U+0027 APOSTROPHE
	"‘", "‘‘", // U+2018 LEFT SINGLE QUOTATION MARK
	"’", "’’", // U+2019 RIGHT SINGLE QUOTATION MARK
	"‚", "‚‚", // U+201A SINGLE LOW-9 QUOTATION MARK
	"‛", "‛‛", // U+201B SINGLE HIGH-REVERSED-9 QUOTATION MARK
)

// psQuote returns s wrapped as a single-quoted PowerShell string literal, with
// every embedded single-quote character (ASCII plus the four Unicode
// variants PowerShell recognises) doubled.
func psQuote(s string) string {
	return "'" + psSingleQuoteReplacer.Replace(s) + "'"
}

// psQuoteList renders a []string as a PowerShell string array literal.
// Example: []string{"A", "B"} -> "@('A','B')". An empty slice renders as "@()".
func psQuoteList(items []string) string {
	if len(items) == 0 {
		return "@()"
	}
	parts := make([]string, len(items))
	for i, it := range items {
		parts[i] = psQuote(it)
	}
	return "@(" + strings.Join(parts, ",") + ")"
}
