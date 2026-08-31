package mode_query

import (
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Run executes query mode for programmatic callers. A non-empty valueName selects a
// single-value read; CLI callers use RunWithValuePresence so they can also select the
// unnamed default value.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to query (e.g. HKLM\SOFTWARE).
//	valueName (string): The value name to read; empty to enumerate the key.
//	recurse (bool): Walk the whole subtree (enumeration) or search recursively (--find).
//	findPattern (string): A case-insensitive substring to search for; empty to not search.
//	searchKeys, searchValues, searchData (bool): With --find, which parts to match.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, recurse bool, findPattern string, searchKeys, searchValues, searchData bool, wow64 ndr.DWORD, debug bool) error {
	return RunWithValuePresence(host, port, creds, keyPath, valueName, valueName != "", recurse, findPattern, searchKeys, searchValues, searchData, wow64, debug)
}

// RunWithValuePresence preserves whether --value was supplied independently of its data,
// allowing an empty name to address the registry's default value.
func RunWithValuePresence(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, valueNameProvided bool, recurse bool, findPattern string, searchKeys, searchValues, searchData bool, wow64 ndr.DWORD, debug bool) error {
	switch {
	case findPattern != "":
		opts := SearchOptions{Keys: searchKeys, Values: searchValues, Data: searchData}
		return SearchKey(host, port, creds, keyPath, findPattern, opts, wow64, debug)
	case valueNameProvided:
		return QueryValue(host, port, creds, keyPath, valueName, wow64, debug)
	default:
		return EnumerateKey(host, port, creds, keyPath, recurse, wow64, debug)
	}
}
