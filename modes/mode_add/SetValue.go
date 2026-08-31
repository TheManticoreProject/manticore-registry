package mode_add

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// SetValue writes a typed value under a registry key on the remote machine. The key path is
// created first (creating any missing intermediate keys) so the behaviour matches reg.exe's
// "add", then the value is written.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path (e.g. HKCU\Software\Acme).
//	valueName (string): The name of the value to write (empty for the default value).
//	value (ms_rrp.RegistryValue): The typed value to write.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func SetValue(host string, port int, creds *credentials.Credentials, keyPath string, valueName string, value ms_rrp.RegistryValue, wow64 ndr.DWORD, debug bool) error {
	if !utils.HasSubkey(keyPath) {
		return fmt.Errorf("the key path %q must include a subkey under a root (e.g. HKLM\\Software\\Acme); values cannot be set on a root key", keyPath)
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	// Ensure the key path exists before writing the value (CreateKeyByPath opens it if it
	// already exists). The returned handle is opened in the requested view, so the value is
	// written there directly rather than reopening via SetValueByPath (which has no view).
	handle, _, err := reg.CreateKeyByPath(keyPath, ms_rrp.KeyWrite|wow64)
	if err != nil {
		return fmt.Errorf("error creating key %q: %s", keyPath, err)
	}
	defer reg.BaseRegCloseKey(handle)

	data := value.Data
	if data == nil {
		data = make([]byte, 0)
	}
	if err := reg.BaseRegSetValue(handle, utils.RegString(valueName), ndr.DWORD(value.Type), data, ndr.DWORD(len(data))); err != nil {
		return fmt.Errorf("error setting value %q in %q: %s", valueName, keyPath, err)
	}

	logger.Print(fmt.Sprintf("[+] Set \x1b[94m%s\\%s\x1b[0m = %s (%s)",
		keyPath, utils.DisplayValueName(valueName), utils.FormatValue(value), utils.TypeName(value.Type)))

	return nil
}
