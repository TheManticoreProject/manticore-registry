package mode_query

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// EnumerateKey lists the subkeys and values directly under a registry key on the remote
// machine. It is used by the "query" mode when no value name is supplied. When recurse is
// true, it walks the entire subtree depth-first.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to enumerate (e.g. HKLM\SOFTWARE).
//	recurse (bool): Walk the whole subtree instead of a single level.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func EnumerateKey(host string, port int, creds *credentials.Credentials, keyPath string, recurse bool, wow64 ndr.DWORD, debug bool) error {
	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	if recurse {
		return enumerateRecursive(reg, keyPath, wow64)
	}
	return enumerateOne(reg, keyPath, wow64)
}

// enumerateOne prints the immediate subkeys and values of a single key.
func enumerateOne(reg *ms_rrp.RemoteRegistry, keyPath string, wow64 ndr.DWORD) error {
	logger.Print(fmt.Sprintf("[>] \x1b[94m%s\x1b[0m", keyPath))

	subkeys, err := utils.EnumKeysView(reg, keyPath, wow64)
	if err != nil {
		return fmt.Errorf("error enumerating subkeys of %q: %s", keyPath, err)
	}
	if len(subkeys) != 0 {
		logger.Print(fmt.Sprintf("[>] Subkeys (\x1b[93m%d\x1b[0m):", len(subkeys)))
		for k, name := range subkeys {
			logger.Print(fmt.Sprintf("  %s \x1b[94m%s\x1b[0m", branch(k, len(subkeys)), name))
		}
	} else {
		logger.Print("[>] Subkeys (0)")
	}

	values, err := utils.EnumValuesView(reg, keyPath, wow64)
	if err != nil {
		return fmt.Errorf("error enumerating values of %q: %s", keyPath, err)
	}
	if len(values) != 0 {
		logger.Print(fmt.Sprintf("[>] Values (\x1b[93m%d\x1b[0m):", len(values)))
		for k, entry := range values {
			logger.Print(fmt.Sprintf("  %s %s    %s    %s", branch(k, len(values)), utils.DisplayValueName(entry.Name), utils.TypeName(entry.Value.Type), utils.FormatValue(entry.Value)))
		}
	} else {
		logger.Print("[>] Values (0)")
	}

	return nil
}

// enumerateRecursive walks the whole subtree under keyPath depth-first, printing each key
// with its values. A subkey that cannot be opened is reported but does not abort the walk.
func enumerateRecursive(reg *ms_rrp.RemoteRegistry, keyPath string, wow64 ndr.DWORD) error {
	values, err := utils.EnumValuesView(reg, keyPath, wow64)
	if err != nil {
		return fmt.Errorf("error enumerating values of %q: %s", keyPath, err)
	}

	logger.Print(fmt.Sprintf("[>] \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m values)", keyPath, len(values)))
	for k, entry := range values {
		logger.Print(fmt.Sprintf("  %s %s    %s    %s", branch(k, len(values)), utils.DisplayValueName(entry.Name), utils.TypeName(entry.Value.Type), utils.FormatValue(entry.Value)))
	}

	subkeys, err := utils.EnumKeysView(reg, keyPath, wow64)
	if err != nil {
		return fmt.Errorf("error enumerating subkeys of %q: %s", keyPath, err)
	}
	var resultErr error
	for _, name := range subkeys {
		if err := enumerateRecursive(reg, keyPath+`\`+name, wow64); err != nil {
			logger.Warn(fmt.Sprintf("%s", err))
			resultErr = errors.Join(resultErr, err)
		}
	}

	return resultErr
}

// branch returns the tree glyph for item index i of a list of n items: the last item closes
// the branch, every other item continues it.
func branch(i, n int) string {
	if i == n-1 {
		return "└──"
	}
	return "├──"
}
