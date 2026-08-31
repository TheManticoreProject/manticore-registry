package mode_find

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Options holds the search criteria of the "find" mode as they come off the command line:
// what to look for (Pattern, Type), how to compare it (Exact, CaseSensitive), where to look
// (Keys, Values, Data) and how far to go (MaxDepth, MaxResults).
type Options struct {
	// Pattern is the string to look for. PatternProvided records option presence separately
	// so an explicitly supplied empty pattern stays a real search: with Exact it matches the
	// unnamed default value, or values holding empty data.
	Pattern         string
	PatternProvided bool

	// Exact matches the whole string instead of a substring. Comparisons fold case unless
	// CaseSensitive is set.
	Exact         bool
	CaseSensitive bool

	// Keys, Values and Data select what the pattern is matched against: key names, value
	// names, and value data. When none is set, all three are searched.
	Keys   bool
	Values bool
	Data   bool

	// Type restricts the search to values of one registry type, as a REG_* mnemonic or a
	// numeric type (see utils.ParseValueType). Empty means any type. Because key names have
	// no type, a type filter excludes key names from the search.
	Type string

	// MaxDepth stops the walk below that many levels under the root key, and MaxResults stops
	// it after that many matches. Zero means no limit.
	MaxDepth   int
	MaxResults int
}

// criteria is the validated, resolved form of the Options a walk runs on.
type criteria struct {
	matcher   matcher
	valueType uint32
	hasType   bool
	keys      bool // match key names
	values    bool // match value names
	data      bool // match value data
}

// scope returns the requested search scope: when the caller selected nothing, key names,
// value names and value data are all searched.
func (o Options) scope() (keys, values, data bool) {
	if !o.Keys && !o.Values && !o.Data {
		return true, true, true
	}
	return o.Keys, o.Values, o.Data
}

// resolve validates the options and turns them into the criteria of a walk.
func (o Options) resolve() (criteria, error) {
	c := criteria{matcher: newMatcher(o.Pattern, o.PatternProvided, o.Exact, o.CaseSensitive)}

	c.hasType = o.Type != ""
	if c.hasType {
		valueType, err := utils.ParseValueType(o.Type)
		if err != nil {
			return criteria{}, err
		}
		c.valueType = valueType
	}

	if c.matcher.matchAll && !c.hasType {
		return criteria{}, fmt.Errorf("nothing to search for: supply -f/--pattern, -t/--type, or both")
	}
	if o.MaxDepth < 0 {
		return criteria{}, fmt.Errorf("invalid --max-depth %d: expected a number of levels, or 0 for no limit", o.MaxDepth)
	}
	if o.MaxResults < 0 {
		return criteria{}, fmt.Errorf("invalid --max-results %d: expected a number of matches, or 0 for no limit", o.MaxResults)
	}

	c.keys, c.values, c.data = o.scope()
	if c.hasType && c.keys {
		// A key name carries no value type, so a type filter and key-name matching cannot both
		// apply: with nothing else in scope the search is empty, otherwise the type filter (the
		// narrower criterion) wins and key names drop out.
		if !c.values && !c.data {
			return criteria{}, fmt.Errorf("empty search scope: --type applies to values, so it cannot be combined with --keys alone")
		}
		if o.Keys {
			logger.Warn("--keys is ignored with --type: key names have no value type.")
		}
		c.keys = false
	}

	return c, nil
}

// Run searches the subtree under keyPath on the remote machine for key names, value names and
// value data matching the given criteria, printing every match and a final count.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The root of the registry subtree to search (e.g. HKLM\SOFTWARE).
//	opts (Options): The search criteria.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the criteria are invalid or the search could not be completed, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, opts Options, wow64 ndr.DWORD, debug bool) error {
	c, err := opts.resolve()
	if err != nil {
		return err
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	f := &finder{
		tree:       remoteEnumerator{reg: reg, wow64: wow64},
		criteria:   c,
		maxDepth:   opts.MaxDepth,
		maxResults: opts.MaxResults,
	}

	logger.Print(fmt.Sprintf("[>] Searching \x1b[94m%s\x1b[0m for %s", keyPath, c.describeSearch()))
	searchErr := f.walk(keyPath, 0)

	if f.stopped {
		logger.Print(fmt.Sprintf("[>] \x1b[93m%d\x1b[0m match(es), stopped at the --max-results limit.", f.matches))
	} else {
		logger.Print(fmt.Sprintf("[>] \x1b[93m%d\x1b[0m match(es).", f.matches))
	}

	return searchErr
}
