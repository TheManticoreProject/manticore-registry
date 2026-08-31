package mode_add

import (
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"

	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run executes the "add" mode. When a value-type flag is supplied it sets that typed value;
// otherwise it just creates the key.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to create or write to.
//	valueName (string): The value name to set; ignored when no value-type flag is supplied.
//	flags (utils.ValueTypeFlags): The mutually exclusive value-type subflags.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the value cannot be parsed or the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, flags utils.ValueTypeFlags, wow64 ndr.DWORD, debug bool) error {
	value, provided, err := utils.BuildRegistryValue(flags)
	if err != nil {
		return err
	}
	if provided {
		return SetValue(host, port, creds, keyPath, valueName, value, wow64, debug)
	}
	return CreateKey(host, port, creds, keyPath, wow64, debug)
}
