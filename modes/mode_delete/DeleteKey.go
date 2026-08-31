package mode_delete

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// DeleteKey deletes a registry key on the remote machine. By default the key must be a leaf
// (no subkeys), matching the underlying BaseRegDeleteKey; when recurse is true the whole
// subtree is removed depth-first. When force is false, the user is prompted for
// confirmation before the deletion.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to delete (e.g. HKCU\Software\Acme).
//	recurse (bool): Delete the key together with all its subkeys.
//	force (bool): Skip the confirmation prompt when true.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func DeleteKey(host string, port int, creds *credentials.Credentials, keyPath string, recurse bool, force bool, wow64 ndr.DWORD, debug bool) error {
	if !utils.HasSubkey(keyPath) {
		return fmt.Errorf("refusing to delete root key %q", keyPath)
	}
	if !force {
		prompt := fmt.Sprintf("Delete the key %s?", keyPath)
		if recurse {
			prompt = fmt.Sprintf("Recursively delete the key %s and all its subkeys?", keyPath)
		}
		if !confirm(prompt) {
			logger.Print("[!] Aborted.")
			return nil
		}
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	if recurse {
		if err := utils.DeleteKeyTreeView(reg, keyPath, wow64); err != nil {
			return fmt.Errorf("error recursively deleting key %q: %s", keyPath, err)
		}
	} else {
		if err := utils.DeleteKeyView(reg, keyPath, wow64); err != nil {
			return fmt.Errorf("error deleting key %q: %s", keyPath, err)
		}
	}

	logger.Print(fmt.Sprintf("[+] Deleted key \x1b[94m%s\x1b[0m", keyPath))

	return nil
}

// confirm prompts the user with a yes/no question on stdin and returns true only if the
// answer starts with 'y' (case-insensitive).
func confirm(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return strings.HasPrefix(answer, "y")
}
