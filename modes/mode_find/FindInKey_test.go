package mode_find

import (
	"fmt"
	"strings"
	"testing"

	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
)

// fakeTree is an in-memory registry subtree: subkeys and values per key path, plus the paths
// whose enumeration must fail, so the walk can be tested without a remote machine. It records
// the keys it was asked about, which is what proves the pruning of a limited walk.
type fakeTree struct {
	subkeys map[string][]string
	values  map[string][]ms_rrp.ValueEntry
	broken  map[string]bool
	visited []string
}

func (t *fakeTree) enumValues(keyPath string) ([]ms_rrp.ValueEntry, error) {
	t.visited = append(t.visited, keyPath)
	if t.broken[keyPath] {
		return nil, fmt.Errorf("ERROR_ACCESS_DENIED")
	}
	return t.values[keyPath], nil
}

func (t *fakeTree) enumKeys(keyPath string) ([]string, error) {
	if t.broken[keyPath] {
		return nil, fmt.Errorf("ERROR_ACCESS_DENIED")
	}
	return t.subkeys[keyPath], nil
}

func (t *fakeTree) visitedKey(keyPath string) bool {
	for _, seen := range t.visited {
		if seen == keyPath {
			return true
		}
	}
	return false
}

// sampleTree is HKLM\SOFTWARE with an Acme subtree three levels deep.
func sampleTree() *fakeTree {
	return &fakeTree{
		subkeys: map[string][]string{
			`HKLM\SOFTWARE`:               {"Acme", "Contoso"},
			`HKLM\SOFTWARE\Acme`:          {"Settings"},
			`HKLM\SOFTWARE\Acme\Settings`: {"Deep"},
			`HKLM\SOFTWARE\Contoso`:       {"AcmeCompat"},
		},
		values: map[string][]ms_rrp.ValueEntry{
			`HKLM\SOFTWARE\Acme`: {
				{Name: "Name", Value: ms_rrp.StringValue("acme-server")},
				{Name: "Enabled", Value: ms_rrp.DwordValue(1)},
			},
			`HKLM\SOFTWARE\Acme\Settings`: {
				{Name: "Acme", Value: ms_rrp.StringValue("nothing to see")},
				{Name: "Port", Value: ms_rrp.DwordValue(443)},
			},
			`HKLM\SOFTWARE\Acme\Settings\Deep`: {
				{Name: "Buried", Value: ms_rrp.StringValue("acme")},
			},
			`HKLM\SOFTWARE\Contoso`: {
				{Name: "Blob", Value: ms_rrp.BinaryValue([]byte{0xde, 0xad})},
			},
		},
		broken: map[string]bool{},
	}
}

// search runs a whole find over the sample tree and returns the finder it ran on.
func search(t *testing.T, tree *fakeTree, opts Options) *finder {
	t.Helper()
	c, err := opts.resolve()
	if err != nil {
		t.Fatalf("unexpected error resolving the criteria: %s", err)
	}
	f := &finder{tree: tree, criteria: c, maxDepth: opts.MaxDepth, maxResults: opts.MaxResults}
	if err := f.walk(`HKLM\SOFTWARE`, 0); err != nil {
		t.Fatalf("unexpected error walking the subtree: %s", err)
	}
	return f
}

func TestWalkMatchesKeysValuesAndData(t *testing.T) {
	// "acme", case-insensitive substring, over the whole scope: the Acme and AcmeCompat keys,
	// the "Acme" value name under Settings, and the "acme-server" / "acme" data.
	f := search(t, sampleTree(), Options{Pattern: "acme", PatternProvided: true})
	if f.matches != 5 {
		t.Fatalf("substring search over the whole scope found %d match(es), want 5", f.matches)
	}
}

func TestWalkNarrowsToTheSelectedScope(t *testing.T) {
	f := search(t, sampleTree(), Options{Pattern: "acme", PatternProvided: true, Keys: true})
	if f.matches != 2 {
		t.Fatalf("key-name search found %d match(es), want 2 (Acme, AcmeCompat)", f.matches)
	}

	f = search(t, sampleTree(), Options{Pattern: "acme", PatternProvided: true, Values: true})
	if f.matches != 1 {
		t.Fatalf("value-name search found %d match(es), want 1 (Settings\\Acme)", f.matches)
	}

	f = search(t, sampleTree(), Options{Pattern: "acme", PatternProvided: true, Data: true})
	if f.matches != 2 {
		t.Fatalf("value-data search found %d match(es), want 2 (acme-server, acme)", f.matches)
	}
}

func TestWalkExactMatchIsWholeString(t *testing.T) {
	// Exact on key names rejects AcmeCompat, and exact on data rejects "acme-server".
	f := search(t, sampleTree(), Options{Pattern: "Acme", PatternProvided: true, Exact: true, Keys: true})
	if f.matches != 1 {
		t.Fatalf("exact key-name search found %d match(es), want 1 (Acme)", f.matches)
	}

	f = search(t, sampleTree(), Options{Pattern: "acme", PatternProvided: true, Exact: true, Data: true})
	if f.matches != 1 {
		t.Fatalf("exact value-data search found %d match(es), want 1 (Deep\\Buried)", f.matches)
	}
}

func TestWalkCaseSensitiveMatch(t *testing.T) {
	f := search(t, sampleTree(), Options{Pattern: "ACME", PatternProvided: true, CaseSensitive: true})
	if f.matches != 0 {
		t.Fatalf("case-sensitive search for %q found %d match(es), want 0", "ACME", f.matches)
	}
}

func TestWalkFiltersOnValueType(t *testing.T) {
	// A type filter with no pattern lists every value of that type.
	f := search(t, sampleTree(), Options{Type: "REG_DWORD"})
	if f.matches != 2 {
		t.Fatalf("type-only search found %d REG_DWORD value(s), want 2 (Enabled, Port)", f.matches)
	}

	f = search(t, sampleTree(), Options{Type: "binary"})
	if f.matches != 1 {
		t.Fatalf("type-only search found %d REG_BINARY value(s), want 1 (Blob)", f.matches)
	}

	// A pattern combined with a type filter only considers values of that type: the Acme and
	// AcmeCompat keys and the REG_SZ hits drop out, leaving nothing.
	f = search(t, sampleTree(), Options{Pattern: "acme", PatternProvided: true, Type: "REG_DWORD"})
	if f.matches != 0 {
		t.Fatalf("search for %q in REG_DWORD values found %d match(es), want 0", "acme", f.matches)
	}

	// A REG_DWORD is matched through the numeric forms of its data, not just its display form.
	f = search(t, sampleTree(), Options{Pattern: "443", PatternProvided: true, Exact: true, Type: "REG_DWORD", Data: true})
	if f.matches != 1 {
		t.Fatalf("search for the decimal form of a REG_DWORD found %d match(es), want 1 (Port)", f.matches)
	}
}

func TestWalkStopsAtTheDepthLimit(t *testing.T) {
	tree := sampleTree()
	// --max-depth 1: the root and its immediate subkeys only. The Acme key name and the data of
	// its values still match, while Contoso\AcmeCompat (depth 2) and everything under Settings
	// are out of reach.
	f := search(t, tree, Options{Pattern: "acme", PatternProvided: true, MaxDepth: 1})
	if f.matches != 2 {
		t.Fatalf("depth-limited search found %d match(es), want 2 (Acme, acme-server)", f.matches)
	}
	if tree.visitedKey(`HKLM\SOFTWARE\Acme\Settings`) {
		t.Fatal("the walk descended past the --max-depth limit")
	}
	if !tree.visitedKey(`HKLM\SOFTWARE\Acme`) {
		t.Fatal("the walk did not search the keys within the --max-depth limit")
	}
}

func TestWalkStopsAtTheResultLimit(t *testing.T) {
	tree := sampleTree()
	f := search(t, tree, Options{Pattern: "acme", PatternProvided: true, MaxResults: 2})
	if f.matches != 2 || !f.stopped {
		t.Fatalf("limited search reported matches=%d stopped=%v, want 2/true", f.matches, f.stopped)
	}
	if tree.visitedKey(`HKLM\SOFTWARE\Contoso`) {
		t.Fatal("the walk kept going after reaching the --max-results limit")
	}
}

func TestWalkKeepsGoingPastAnInaccessibleKey(t *testing.T) {
	tree := sampleTree()
	tree.broken[`HKLM\SOFTWARE\Acme`] = true

	c, err := Options{Pattern: "acme", PatternProvided: true}.resolve()
	if err != nil {
		t.Fatalf("unexpected error resolving the criteria: %s", err)
	}
	f := &finder{tree: tree, criteria: c}
	err = f.walk(`HKLM\SOFTWARE`, 0)
	if err == nil {
		t.Fatal("an inaccessible key was not reported as an error")
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%q", `HKLM\SOFTWARE\Acme`)) {
		t.Fatalf("the error %q does not name the inaccessible key", err)
	}
	// Acme itself and its whole branch are unreadable, but the sibling branch is still searched:
	// the Acme and AcmeCompat key names remain matched.
	if f.matches != 2 {
		t.Fatalf("search over a partly inaccessible subtree found %d match(es), want 2", f.matches)
	}
	if !tree.visitedKey(`HKLM\SOFTWARE\Contoso`) {
		t.Fatal("the walk gave up on the rest of the subtree after an inaccessible key")
	}
}
