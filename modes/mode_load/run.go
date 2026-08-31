package mode_load

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run loads a hive file on the remote machine into a new subkey under a root key
// (HKLM or HKU). The key path names the mount point (e.g. HKLM\TempHive); its leaf is
// created by the load. The file path is interpreted on the target host and the operation
// requires SeRestorePrivilege/SeBackupPrivilege.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The mount point for the hive (e.g. HKLM\TempHive).
//	filePath (string): The source hive file path on the remote machine.
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, filePath string, debug bool) error {
	root, subkey := utils.SplitRootPath(keyPath)
	if subkey == "" {
		return fmt.Errorf("the key path %q must include a subkey name to mount the hive under (e.g. HKLM\\TempHive)", keyPath)
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	rootHandle, err := utils.OpenRoot(reg, root, ms_rrp.MaximumAllowed)
	if err != nil {
		return fmt.Errorf("error opening root %q: %s", root, err)
	}
	defer reg.BaseRegCloseKey(rootHandle)

	if err := reg.BaseRegLoadKey(rootHandle, utils.RegString(subkey), utils.RegString(filePath)); err != nil {
		return fmt.Errorf("error loading %q into %q: %s", filePath, keyPath, err)
	}

	logger.Print(fmt.Sprintf("[+] Loaded \x1b[94m%s\x1b[0m as \x1b[94m%s\x1b[0m", filePath, keyPath))

	return nil
}
