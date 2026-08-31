package mode_delete

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// DeleteAllValues removes every value under a registry key while leaving the key and its
// subkeys intact (reg.exe's DELETE /va). When force is false, the user is prompted for
// confirmation before the deletion.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path whose values are deleted (e.g. HKCU\Software\Acme).
//	force (bool): Skip the confirmation prompt when true.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func DeleteAllValues(host string, port int, creds *credentials.Credentials, keyPath string, force bool, wow64 ndr.DWORD, debug bool) error {
	if !utils.HasSubkey(keyPath) {
		return fmt.Errorf("the key path %q must include a subkey under a root (e.g. HKLM\\Software\\Acme); root keys hold no values", keyPath)
	}

	if !force {
		if !confirm(fmt.Sprintf("Delete ALL values under %s?", keyPath)) {
			logger.Print("[!] Aborted.")
			return nil
		}
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	values, err := utils.EnumValuesView(reg, keyPath, wow64)
	if err != nil {
		return fmt.Errorf("error enumerating values of %q: %s", keyPath, err)
	}

	deleted := 0
	var resultErr error
	for _, entry := range values {
		if err := utils.DeleteValueView(reg, keyPath, entry.Name, wow64); err != nil {
			logger.Warn(fmt.Sprintf("error deleting value %q in %q: %s", entry.Name, keyPath, err))
			resultErr = errors.Join(resultErr, fmt.Errorf("error deleting value %q in %q: %w", entry.Name, keyPath, err))
			continue
		}
		deleted++
	}

	logger.Print(fmt.Sprintf("[+] Deleted \x1b[93m%d\x1b[0m value(s) under \x1b[94m%s\x1b[0m", deleted, keyPath))

	return resultErr
}
