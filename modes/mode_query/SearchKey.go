package mode_query

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// SearchOptions selects what a search matches against. When none is set, all three are
// searched (matching reg.exe's default behaviour for QUERY /f).
type SearchOptions struct {
	Keys   bool // match subkey names
	Values bool // match value names
	Data   bool // match value data (string-decoded)
}

// resolve returns the effective scope: if nothing was selected, search everything.
func (o SearchOptions) resolve() (keys, values, data bool) {
	if !o.Keys && !o.Values && !o.Data {
		return true, true, true
	}
	return o.Keys, o.Values, o.Data
}

// SearchKey recursively searches the subtree under keyPath for a (case-insensitive)
// substring, reporting matching key names, value names, and/or value data.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to search under (e.g. HKLM\SOFTWARE).
//	pattern (string): The substring to match (case-insensitive).
//	opts (SearchOptions): What to match against (keys/values/data).
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func SearchKey(host string, port int, creds *credentials.Credentials, keyPath string, pattern string, opts SearchOptions, wow64 ndr.DWORD, debug bool) error {
	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	keys, values, data := opts.resolve()
	needle := strings.ToLower(pattern)

	logger.Print(fmt.Sprintf("[>] Searching \x1b[94m%s\x1b[0m for \x1b[93m%q\x1b[0m", keyPath, pattern))
	matches, searchErr := searchRecursive(reg, keyPath, needle, keys, values, data, wow64)
	logger.Print(fmt.Sprintf("[>] %d match(es).", matches))

	return searchErr
}

// searchRecursive walks the subtree and prints matches, returning the number found. Subkeys
// that cannot be opened are reported but do not abort the walk.
func searchRecursive(reg *ms_rrp.RemoteRegistry, keyPath, needle string, keys, values, data bool, wow64 ndr.DWORD) (int, error) {
	matches := 0
	var resultErr error

	if values || data {
		entries, err := utils.EnumValuesView(reg, keyPath, wow64)
		if err != nil {
			logger.Warn(fmt.Sprintf("error enumerating values of %q: %s", keyPath, err))
			resultErr = errors.Join(resultErr, fmt.Errorf("error enumerating values of %q: %w", keyPath, err))
		}
		for _, entry := range entries {
			if values && strings.Contains(strings.ToLower(entry.Name), needle) {
				logger.Print(fmt.Sprintf("    [value name] \x1b[94m%s\\%s\x1b[0m", keyPath, utils.DisplayValueName(entry.Name)))
				matches++
			}
			if data && strings.Contains(strings.ToLower(utils.FormatValue(entry.Value)), needle) {
				logger.Print(fmt.Sprintf("    [value data] \x1b[94m%s\\%s\x1b[0m = %s", keyPath, utils.DisplayValueName(entry.Name), utils.FormatValue(entry.Value)))
				matches++
			}
		}
	}

	subkeys, err := utils.EnumKeysView(reg, keyPath, wow64)
	if err != nil {
		logger.Warn(fmt.Sprintf("error enumerating subkeys of %q: %s", keyPath, err))
		return matches, errors.Join(resultErr, fmt.Errorf("error enumerating subkeys of %q: %w", keyPath, err))
	}
	for _, name := range subkeys {
		if keys && strings.Contains(strings.ToLower(name), needle) {
			logger.Print(fmt.Sprintf("    [key] \x1b[94m%s\\%s\x1b[0m", keyPath, name))
			matches++
		}
		childMatches, err := searchRecursive(reg, keyPath+`\`+name, needle, keys, values, data, wow64)
		matches += childMatches
		resultErr = errors.Join(resultErr, err)
	}

	return matches, resultErr
}
