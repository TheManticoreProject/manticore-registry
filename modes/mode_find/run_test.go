package mode_find

import (
	"strings"
	"testing"

	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

func TestMatcherMatchModes(t *testing.T) {
	tests := []struct {
		name          string
		pattern       string
		provided      bool
		exact         bool
		caseSensitive bool
		candidate     string
		want          bool
	}{
		{name: "contains-substring", pattern: "cme", provided: true, candidate: "Acme", want: true},
		{name: "contains-folds-case", pattern: "ACME", provided: true, candidate: "acme-server", want: true},
		{name: "contains-case-sensitive-miss", pattern: "ACME", provided: true, caseSensitive: true, candidate: "acme-server", want: false},
		{name: "contains-case-sensitive-hit", pattern: "Acme", provided: true, caseSensitive: true, candidate: "Acme-server", want: true},
		{name: "exact-whole-string", pattern: "Acme", provided: true, exact: true, candidate: "Acme", want: true},
		{name: "exact-rejects-substring", pattern: "Acme", provided: true, exact: true, candidate: "Acme-server", want: false},
		{name: "exact-folds-case", pattern: "acme", provided: true, exact: true, candidate: "ACME", want: true},
		{name: "exact-case-sensitive-miss", pattern: "acme", provided: true, exact: true, caseSensitive: true, candidate: "ACME", want: false},
		{name: "exact-empty-pattern-matches-empty", pattern: "", provided: true, exact: true, candidate: "", want: true},
		{name: "exact-empty-pattern-rejects-other", pattern: "", provided: true, exact: true, candidate: "Acme", want: false},
		{name: "no-pattern-matches-everything", pattern: "", provided: false, candidate: "anything", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMatcher(tt.pattern, tt.provided, tt.exact, tt.caseSensitive)
			if got := m.matches(tt.candidate); got != tt.want {
				t.Fatalf("matches(%q) = %v, want %v", tt.candidate, got, tt.want)
			}
		})
	}
}

func TestMatcherMatchesAnyValueRendering(t *testing.T) {
	// A REG_DWORD is searchable through its decimal, hex and displayed forms alike.
	m := newMatcher("16", true, true, false)
	if !m.matchesAny(utils.ValueDataCandidates(ms_rrp.DwordValue(16))) {
		t.Fatal("exact search for the decimal form of a REG_DWORD did not match")
	}
	m = newMatcher("0x10", true, true, false)
	if !m.matchesAny(utils.ValueDataCandidates(ms_rrp.DwordValue(16))) {
		t.Fatal("exact search for the hex form of a REG_DWORD did not match")
	}
	m = newMatcher("17", true, true, false)
	if m.matchesAny(utils.ValueDataCandidates(ms_rrp.DwordValue(16))) {
		t.Fatal("exact search matched a REG_DWORD holding another number")
	}

	// Each item of a REG_MULTI_SZ is matchable on its own, not only the joined rendering.
	m = newMatcher("b", true, true, false)
	if !m.matchesAny(utils.ValueDataCandidates(ms_rrp.MultiStringValue([]string{"a", "b", "c"}))) {
		t.Fatal("exact search for one item of a REG_MULTI_SZ did not match")
	}
}

func TestResolveDefaultsToTheWholeScope(t *testing.T) {
	c, err := Options{Pattern: "Acme", PatternProvided: true}.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !c.keys || !c.values || !c.data {
		t.Fatalf("default scope was keys=%v values=%v data=%v, want all three", c.keys, c.values, c.data)
	}
	if c.hasType {
		t.Fatal("no type filter was requested but one was resolved")
	}
}

func TestResolveHonorsAnExplicitScope(t *testing.T) {
	c, err := Options{Pattern: "Acme", PatternProvided: true, Keys: true}.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !c.keys || c.values || c.data {
		t.Fatalf("scope was keys=%v values=%v data=%v, want key names only", c.keys, c.values, c.data)
	}
}

func TestResolveParsesTheTypeFilterAndDropsKeyNames(t *testing.T) {
	c, err := Options{Pattern: "Acme", PatternProvided: true, Type: "multi-sz"}.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !c.hasType || c.valueType != ms_rrp.RegMultiSz {
		t.Fatalf("type filter resolved to hasType=%v type=%#x, want REG_MULTI_SZ", c.hasType, c.valueType)
	}
	// Key names carry no value type, so they leave the scope rather than matching everything.
	if c.keys {
		t.Fatal("key names stayed in the scope of a search filtered by value type")
	}
	if !c.values || !c.data {
		t.Fatalf("scope was values=%v data=%v, want both", c.values, c.data)
	}
}

func TestResolveAcceptsATypeOnlySearch(t *testing.T) {
	c, err := Options{Type: "REG_BINARY"}.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if !c.matcher.matchAll {
		t.Fatal("a search by type alone should match every value of that type")
	}
}

func TestResolveRejectsInvalidCriteria(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want string
	}{
		{name: "no-pattern-no-type", opts: Options{}, want: "nothing to search for"},
		{name: "unknown-type", opts: Options{Pattern: "x", PatternProvided: true, Type: "REG_NOPE"}, want: "unknown registry value type"},
		{name: "keys-only-with-type", opts: Options{Pattern: "x", PatternProvided: true, Keys: true, Type: "REG_SZ"}, want: "empty search scope"},
		{name: "negative-max-depth", opts: Options{Pattern: "x", PatternProvided: true, MaxDepth: -1}, want: "invalid --max-depth"},
		{name: "negative-max-results", opts: Options{Pattern: "x", PatternProvided: true, MaxResults: -2}, want: "invalid --max-results"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.opts.resolve(); err == nil {
				t.Fatal("expected an error, got none")
			} else if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestCountStopsAtTheMaxResultsLimit(t *testing.T) {
	f := &finder{maxResults: 2}
	f.count()
	if f.stopped {
		t.Fatal("the walk stopped before reaching the limit")
	}
	f.count()
	if !f.stopped || f.matches != 2 {
		t.Fatalf("after the limit: stopped=%v matches=%d, want true/2", f.stopped, f.matches)
	}

	unlimited := &finder{}
	for range 100 {
		unlimited.count()
	}
	if unlimited.stopped {
		t.Fatal("--max-results 0 should never stop the walk")
	}
}

func TestDescribeScopeAndMatchMode(t *testing.T) {
	c, err := Options{Pattern: "Acme", PatternProvided: true, Exact: true, CaseSensitive: true, Values: true}.resolve()
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if got := c.describeScope(); got != "value names" {
		t.Fatalf("describeScope() = %q, want \"value names\"", got)
	}
	if got := c.matcher.describe(); got != "exact, case-sensitive" {
		t.Fatalf("describe() = %q, want \"exact, case-sensitive\"", got)
	}
}
