package mode_save

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run saves a registry key and its subtree to a hive file on the remote machine. The
// file path is interpreted on the target host (relative paths resolve against the Remote
// Registry service's working directory), and the operation requires SeBackupPrivilege.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to save (e.g. HKLM\SOFTWARE\Acme).
//	filePath (string): The destination hive file path on the remote machine.
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

	handle, err := reg.OpenKeyByPath(keyPath, ms_rrp.KeyRead)
	if err != nil {
		return fmt.Errorf("error opening key %q: %s", keyPath, err)
	}
	defer reg.BaseRegCloseKey(handle)

	if err := reg.BaseRegSaveKey(handle, utils.RegString(filePath), nil); err != nil {
		return fmt.Errorf("error saving key %q to %q: %s", keyPath, filePath, err)
	}

	logger.Print(fmt.Sprintf("[+] Saved key \x1b[94m%s\x1b[0m to \x1b[94m%s\x1b[0m on the remote host", keyPath, filePath))

	return nil
}
