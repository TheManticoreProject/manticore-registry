package mode_restore

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run restores a hive file on the remote machine into an existing registry key,
// overwriting its contents. The file path is interpreted on the target host and the
// operation requires SeRestorePrivilege.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to restore into (e.g. HKLM\SOFTWARE\Acme).
//	filePath (string): The source hive file path on the remote machine.
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, filePath string, debug bool) error {
	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	handle, err := reg.OpenKeyByPath(keyPath, ms_rrp.KeyWrite)
	if err != nil {
		return fmt.Errorf("error opening key %q: %s", keyPath, err)
	}
	defer reg.BaseRegCloseKey(handle)

	// flags = 0: default restore behaviour (REG_FORCE_RESTORE is not requested).
	if err := reg.BaseRegRestoreKey(handle, utils.RegString(filePath), 0); err != nil {
		return fmt.Errorf("error restoring %q into key %q: %s", filePath, keyPath, err)
	}

	logger.Print(fmt.Sprintf("[+] Restored \x1b[94m%s\x1b[0m into key \x1b[94m%s\x1b[0m", filePath, keyPath))

	return nil
}
