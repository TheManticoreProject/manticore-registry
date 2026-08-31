package mode_find

import "strings"

// matcher decides whether a single string satisfies the search criteria. A search with no
// pattern (a search by --type alone) matches everything it is offered, so the type filter
// applied by the caller becomes the only selection criterion.
type matcher struct {
	original      string // the pattern as supplied, for display
	needle        string // the pattern, folded to lower case for a case-insensitive search
	exact         bool
	caseSensitive bool
	matchAll      bool // no pattern was supplied: every candidate matches
}

// newMatcher builds the matcher for a search. patternProvided is tracked separately from the
// pattern itself so that an explicitly supplied empty pattern stays a real search (it matches
// the unnamed default value, or values holding empty data, when combined with --exact).
func newMatcher(pattern string, patternProvided, exact, caseSensitive bool) matcher {
	needle := pattern
	if !caseSensitive {
		needle = strings.ToLower(needle)
	}
	return matcher{
		original:      pattern,
		needle:        needle,
		exact:         exact,
		caseSensitive: caseSensitive,
		matchAll:      !patternProvided,
	}
}

// matches reports whether candidate satisfies the search criteria.
func (m matcher) matches(candidate string) bool {
	if m.matchAll {
		return true
	}
	if !m.caseSensitive {
		candidate = strings.ToLower(candidate)
	}
	if m.exact {
		return candidate == m.needle
	}
	return strings.Contains(candidate, m.needle)
}

// matchesAny reports whether at least one of the candidate renderings of a value satisfies
// the search criteria.
func (m matcher) matchesAny(candidates []string) bool {
	for _, candidate := range candidates {
		if m.matches(candidate) {
			return true
		}
	}
	return false
}

// describe renders the match mode for the search header.
func (m matcher) describe() string {
	mode := "contains"
	if m.exact {
		mode = "exact"
	}
	if m.caseSensitive {
		return mode + ", case-sensitive"
	}
	return mode + ", case-insensitive"
}
