package mode_copy

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run recursively copies a registry key (its values and its whole subtree) from a
// source path to a destination path on the same remote machine, creating the destination
// keys as needed (reg.exe COPY semantics).
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	srcPath (string): The source registry key path.
//	dstPath (string): The destination registry key path.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply to both keys (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, srcPath string, dstPath string, wow64 ndr.DWORD, debug bool) error {
	if !utils.HasSubkey(dstPath) {
		return fmt.Errorf("the destination key path %q must include a subkey under a root (e.g. HKLM\\Software\\AcmeBackup); cannot copy into a root key", dstPath)
	}
	if utils.CanonicalKeyPath(srcPath) == utils.CanonicalKeyPath(dstPath) {
		return fmt.Errorf("the source and destination keys are the same key (%q); nothing to copy", srcPath)
	}
	if utils.IsKeyDescendant(srcPath, dstPath) {
		return fmt.Errorf("the destination key %q cannot be inside the source key %q", dstPath, srcPath)
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	keys, values, err := copyRecursive(reg, srcPath, dstPath, wow64)
	if err != nil {
		return fmt.Errorf("copy incomplete after %d key(s) and %d value(s): %w", keys, values, err)
	}

	logger.Print(fmt.Sprintf("[+] Copied \x1b[94m%s\x1b[0m to \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m keys, \x1b[93m%d\x1b[0m values)", srcPath, dstPath, keys, values))
	return nil
}

// copyRecursive copies srcPath onto dstPath and recurses into subkeys, returning the number
// of keys and values copied. Per-value and per-subtree failures are accumulated so the
// caller receives a non-nil error even when other independent items can still be copied.
func copyRecursive(reg *ms_rrp.RemoteRegistry, srcPath, dstPath string, wow64 ndr.DWORD) (keys, values int, resultErr error) {
	// Validate the source level before changing the destination. A missing or unreadable
	// source must never create an empty destination and report success.
	entries, err := utils.EnumValuesView(reg, srcPath, wow64)
	if err != nil {
		return 0, 0, fmt.Errorf("error reading values of %q: %w", srcPath, err)
	}
	subkeys, err := utils.EnumKeysView(reg, srcPath, wow64)
	if err != nil {
		return 0, 0, fmt.Errorf("error reading subkeys of %q: %w", srcPath, err)
	}

	// Ensure the destination key exists; without it this subtree cannot be copied.
	handle, _, err := reg.CreateKeyByPath(dstPath, ms_rrp.KeyWrite|wow64)
	if err != nil {
		return 0, 0, fmt.Errorf("error creating destination key %q: %w", dstPath, err)
	}
	reg.BaseRegCloseKey(handle)
	keys++

	// Copy the values of this key.
	for _, entry := range entries {
		if err := utils.SetValueView(reg, dstPath, entry.Name, entry.Value, wow64); err != nil {
			logger.Warn(fmt.Sprintf("error writing value %q to %q: %s", entry.Name, dstPath, err))
			resultErr = errors.Join(resultErr, fmt.Errorf("error writing value %q to %q: %w", entry.Name, dstPath, err))
			continue
		}
		values++
	}

	// Recurse into subkeys.
	for _, name := range subkeys {
		k, v, err := copyRecursive(reg, srcPath+`\`+name, dstPath+`\`+name, wow64)
		keys += k
		values += v
		resultErr = errors.Join(resultErr, err)
	}

	return keys, values, resultErr
}
