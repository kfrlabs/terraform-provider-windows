package winclient

import (
	"strings"
	"testing"
)

// Table-driven coverage for every character PowerShell treats as a single
// quote (see psquote.go). Each must be doubled, mirroring .NET's
// EscapeSingleQuotedStringContent.
func TestPsQuoteUnicodeQuotes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "''"},
		{"plain", "hello", "'hello'"},
		{"ascii apostrophe", "it's", "'it''s'"},
		{"multiple ascii", "a'b'c", "'a''b''c'"},
		{"U+2018 left single", "a‘b", "'a‘‘b'"},
		{"U+2019 right single", "a’b", "'a’’b'"},
		{"U+201A low-9", "a‚b", "'a‚‚b'"},
		{"U+201B high-reversed-9", "a‛b", "'a‛‛b'"},
		{"all five together", "'‘’‚‛", "'''‘‘’’‚‚‛‛'"},
		{
			// Injection payload from the issue: the smart-quote terminator
			// must be neutralised so the literal cannot be broken out of.
			"injection terminator",
			"x’; Write-Output INJECTED; ’",
			"'x’’; Write-Output INJECTED; ’’'",
		},
		{
			"mixed ascii and unicode",
			"it’s a ‘test’ with 'quotes'",
			"'it’’s a ‘‘test’’ with ''quotes'''",
		},
		{"lone unicode quote", "’", "'’’'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := psQuote(tc.in); got != tc.want {
				t.Errorf("psQuote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The quoted literal must never contain an unescaped quote character: after
// stripping the outer delimiters, no single raw quote rune may remain that is
// not part of a doubled pair.
func TestPsQuoteOutputHasNoBareQuotes(t *testing.T) {
	quotes := []rune{'\'', '‘', '’', '‚', '‛'}
	inputs := []string{
		"x’; Write-Output INJECTED; ’",
		"‘quoted’ ‚and‛ 'all'",
		"copy-pasted “smart” ’text’",
	}
	for _, in := range inputs {
		got := psQuote(in)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Fatalf("psQuote(%q) = %q: missing outer delimiters", in, got)
		}
		inner := got[1 : len(got)-1]
		runes := []rune(inner)
		for i := 0; i < len(runes); i++ {
			for _, q := range quotes {
				if runes[i] == q {
					if i+1 >= len(runes) || runes[i+1] != q {
						t.Errorf("psQuote(%q) = %q: bare %U at position %d", in, got, q, i)
					} else {
						i++ // skip the second half of the escaped pair
					}
					break
				}
			}
		}
	}
}

// psQuoteList must route every element through the same escaping.
func TestPsQuoteListUnicodeQuotes(t *testing.T) {
	if got := psQuoteList(nil); got != "@()" {
		t.Errorf("nil list = %q", got)
	}
	if got := psQuoteList([]string{}); got != "@()" {
		t.Errorf("empty list = %q", got)
	}
	if got := psQuoteList([]string{"A", "B"}); got != "@('A','B')" {
		t.Errorf("two items = %q", got)
	}
	if got := psQuoteList([]string{"it’s"}); got != "@('it’’s')" {
		t.Errorf("unicode quote in item = %q", got)
	}
	if got := psQuoteList([]string{"a‘b", "c’d", "e‚f", "g‛h", "i'j"}); got != "@('a‘‘b','c’’d','e‚‚f','g‛‛h','i''j')" {
		t.Errorf("all quote variants = %q", got)
	}
}
