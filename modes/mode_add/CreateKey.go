package mode_add

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// CreateKey creates a registry key on the remote machine, creating any missing intermediate
// keys along the path. It is used by the "add" mode when no value is supplied.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to create (e.g. HKCU\Software\Acme).
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func CreateKey(host string, port int, creds *credentials.Credentials, keyPath string, wow64 ndr.DWORD, debug bool) error {
	if !utils.HasSubkey(keyPath) {
		return fmt.Errorf("the key path %q must include a subkey under a root (e.g. HKLM\\Software\\Acme); root keys cannot be created", keyPath)
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	handle, disposition, err := reg.CreateKeyByPath(keyPath, ms_rrp.KeyWrite|wow64)
	if err != nil {
		return fmt.Errorf("error creating key %q: %s", keyPath, err)
	}
	defer reg.BaseRegCloseKey(handle)

	if disposition == ms_rrp.RegOpenedExistingKey {
		logger.Print(fmt.Sprintf("[!] Key \x1b[94m%s\x1b[0m already exists.", keyPath))
	} else {
		logger.Print(fmt.Sprintf("[+] Created key \x1b[94m%s\x1b[0m", keyPath))
	}

	return nil
}
