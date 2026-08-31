package mode_delete

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// DeleteValue removes a single value from a registry key on the remote machine. When force is
// false, the user is prompted for confirmation before the deletion.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path (e.g. HKCU\Software\Acme).
//	valueName (string): The name of the value to delete (empty for the default value).
//	force (bool): Skip the confirmation prompt when true.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func DeleteValue(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, force bool, wow64 ndr.DWORD, debug bool) error {
	if !utils.HasSubkey(keyPath) {
		return fmt.Errorf("the key path %q must include a subkey under a root (e.g. HKLM\\Software\\Acme); root keys hold no values", keyPath)
	}

	displayName := utils.DisplayValueName(valueName)

	if !force {
		if !confirm(fmt.Sprintf("Delete the value %s in %s?", displayName, keyPath)) {
			logger.Print("[!] Aborted.")
			return nil
		}
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := utils.DeleteValueView(reg, keyPath, valueName, wow64); err != nil {
		return fmt.Errorf("error deleting value %q in %q: %s", valueName, keyPath, err)
	}

	logger.Print(fmt.Sprintf("[+] Deleted value \x1b[94m%s\\%s\x1b[0m", keyPath, displayName))

	return nil
}
