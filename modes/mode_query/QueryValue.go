package mode_query

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// QueryValue reads a single registry value on the remote machine and prints it.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path (e.g. HKLM\SOFTWARE\...).
//	valueName (string): The name of the value to read.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func QueryValue(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, wow64 ndr.DWORD, debug bool) error {
	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	value, err := utils.QueryValueView(reg, keyPath, valueName, wow64)
	if err != nil {
		return fmt.Errorf("error querying value %q in %q: %s", valueName, keyPath, err)
	}

	logger.Print(fmt.Sprintf("[>] \x1b[94m%s\x1b[0m", keyPath))
	logger.Print(fmt.Sprintf("  └── %s    %s    %s", utils.DisplayValueName(valueName), utils.TypeName(value.Type), utils.FormatValue(value)))

	return nil
}
