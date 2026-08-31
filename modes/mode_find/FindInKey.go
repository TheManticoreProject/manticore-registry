package mode_find

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// registryEnumerator is the slice of the remote registry a search needs: the values and the
// immediate subkeys of a key. The walk goes through it rather than calling the registry
// directly, so the search logic can also be exercised against an in-memory tree.
type registryEnumerator interface {
	enumValues(keyPath string) ([]ms_rrp.ValueEntry, error)
	enumKeys(keyPath string) ([]string, error)
}

// remoteEnumerator reads a live remote registry in one WOW64 view.
type remoteEnumerator struct {
	reg   *ms_rrp.RemoteRegistry
	wow64 ndr.DWORD
}

func (e remoteEnumerator) enumValues(keyPath string) ([]ms_rrp.ValueEntry, error) {
	return utils.EnumValuesView(e.reg, keyPath, e.wow64)
}

func (e remoteEnumerator) enumKeys(keyPath string) ([]string, error) {
	return utils.EnumKeysView(e.reg, keyPath, e.wow64)
}

// finder walks a registry subtree and reports what matches the search criteria. It carries the
// running match count so the walk can stop at the --max-results limit.
type finder struct {
	tree registryEnumerator
	criteria

	maxDepth   int // levels below the root to search; 0 for no limit
	maxResults int // matches after which to stop; 0 for no limit

	matches int
	stopped bool // the --max-results limit was reached and the walk was cut short
}

// describeSearch renders the criteria of the search for its header line: what is looked for,
// how it is compared, and where.
func (c criteria) describeSearch() string {
	if c.matcher.matchAll {
		return fmt.Sprintf("every value of type \x1b[93m%s\x1b[0m", utils.TypeName(c.valueType))
	}
	target := fmt.Sprintf("\x1b[93m%q\x1b[0m (%s) in %s", c.matcher.original, c.matcher.describe(), c.describeScope())
	if c.hasType {
		target += fmt.Sprintf(" of \x1b[93m%s\x1b[0m values", utils.TypeName(c.valueType))
	}
	return target
}

// describeScope renders the effective search scope, for the search header.
func (c criteria) describeScope() string {
	parts := make([]string, 0, 3)
	if c.keys {
		parts = append(parts, "key names")
	}
	if c.values {
		parts = append(parts, "value names")
	}
	if c.data {
		parts = append(parts, "value data")
	}
	return strings.Join(parts, ", ")
}

// walk searches one key, then recurses into its subkeys depth-first. depth is the number of
// levels the key sits below the root of the search. Key names are matched as the subkeys of a
// key are enumerated, so the root of the search is never matched by its own name. A key whose values or subkeys cannot be
// read is reported but does not abort the walk, so an inaccessible branch never hides the rest
// of the results; the errors are joined and returned.
func (f *finder) walk(keyPath string, depth int) error {
	if f.stopped {
		return nil
	}

	var resultErr error

	if f.values || f.data {
		if err := f.searchValues(keyPath); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}
	if f.stopped {
		return resultErr
	}

	// Subkeys sit one level deeper, so at the depth limit there is nothing left to visit.
	if f.maxDepth > 0 && depth >= f.maxDepth {
		return resultErr
	}

	subkeys, err := f.tree.enumKeys(keyPath)
	if err != nil {
		logger.Warn(fmt.Sprintf("error enumerating subkeys of %q: %s", keyPath, err))
		return errors.Join(resultErr, fmt.Errorf("error enumerating subkeys of %q: %w", keyPath, err))
	}

	for _, name := range subkeys {
		subkeyPath := keyPath + `\` + name
		if f.keys && f.matcher.matches(name) {
			f.reportKey(subkeyPath)
			if f.stopped {
				return resultErr
			}
		}
		resultErr = errors.Join(resultErr, f.walk(subkeyPath, depth+1))
		if f.stopped {
			return resultErr
		}
	}

	return resultErr
}

// searchValues matches the values of a single key against the criteria. A value is considered
// only when its type passes the type filter; a value can then match on its name, on its data,
// or, in a search by type alone, on its type.
func (f *finder) searchValues(keyPath string) error {
	entries, err := f.tree.enumValues(keyPath)
	if err != nil {
		logger.Warn(fmt.Sprintf("error enumerating values of %q: %s", keyPath, err))
		return fmt.Errorf("error enumerating values of %q: %w", keyPath, err)
	}

	for _, entry := range entries {
		if f.hasType && entry.Value.Type != f.valueType {
			continue
		}

		// With no pattern, the type filter is the whole search: the value matches once, on its
		// type, rather than once per scope it trivially satisfies.
		if f.matcher.matchAll {
			f.reportValue("value type", keyPath, entry)
			if f.stopped {
				return nil
			}
			continue
		}

		if f.values && f.matcher.matches(entry.Name) {
			f.reportValue("value name", keyPath, entry)
			if f.stopped {
				return nil
			}
		}
		if f.data && f.matcher.matchesAny(utils.ValueDataCandidates(entry.Value)) {
			f.reportValue("value data", keyPath, entry)
			if f.stopped {
				return nil
			}
		}
	}

	return nil
}

// reportKey prints a matching key and accounts for it.
func (f *finder) reportKey(keyPath string) {
	logger.Print(fmt.Sprintf("    [key]        \x1b[94m%s\x1b[0m", keyPath))
	f.count()
}

// reportValue prints a matching value, with the reason it matched, and accounts for it.
func (f *finder) reportValue(kind, keyPath string, entry ms_rrp.ValueEntry) {
	logger.Print(fmt.Sprintf("    [%s] \x1b[94m%s\\%s\x1b[0m    %s    %s",
		kind, keyPath, utils.DisplayValueName(entry.Name), utils.TypeName(entry.Value.Type), utils.FormatValue(entry.Value)))
	f.count()
}

// count records a match and raises the stop flag once the --max-results limit is reached.
func (f *finder) count() {
	f.matches++
	if f.maxResults > 0 && f.matches >= f.maxResults {
		f.stopped = true
	}
}
