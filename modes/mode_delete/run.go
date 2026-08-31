package mode_delete

import (
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// Run executes delete mode for programmatic callers. A non-empty valueName selects a
// single-value deletion; CLI callers use RunWithValuePresence so they can also select the
// unnamed default value.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to operate on.
//	valueName (string): The value name to delete; empty to delete the key.
//	recurse (bool): Delete the key together with all its subkeys.
//	allValues (bool): Delete all values under the key, keeping the key and its subkeys.
//	force (bool): Delete without prompting for confirmation.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, recurse, allValues, force bool, wow64 ndr.DWORD, debug bool) error {
	return RunWithValuePresence(host, port, creds, keyPath, valueName, valueName != "", recurse, allValues, force, wow64, debug)
}

// RunWithValuePresence preserves whether --value was supplied independently of its data,
// allowing an empty name to address the registry's default value.
func RunWithValuePresence(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, valueNameProvided bool, recurse, allValues, force bool, wow64 ndr.DWORD, debug bool) error {
	switch {
	case allValues:
		return DeleteAllValues(host, port, creds, keyPath, force, wow64, debug)
	case valueNameProvided:
		return DeleteValue(host, port, creds, keyPath, valueName, force, wow64, debug)
	default:
		return DeleteKey(host, port, creds, keyPath, recurse, force, wow64, debug)
	}
}
