package mode_unload

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run unloads a previously loaded hive from a subkey under a root key (HKLM or HKU).
// The key path names the mount point to unload (e.g. HKLM\TempHive).
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The mount point to unload (e.g. HKLM\TempHive).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, debug bool) error {
	root, subkey := utils.SplitRootPath(keyPath)
	if subkey == "" {
		return fmt.Errorf("the key path %q must include the mounted subkey name to unload (e.g. HKLM\\TempHive)", keyPath)
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

	if err := reg.BaseRegUnLoadKey(rootHandle, utils.RegString(subkey)); err != nil {
		return fmt.Errorf("error unloading %q: %s", keyPath, err)
	}

	logger.Print(fmt.Sprintf("[+] Unloaded \x1b[94m%s\x1b[0m", keyPath))

	return nil
}
