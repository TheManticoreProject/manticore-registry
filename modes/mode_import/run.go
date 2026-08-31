package mode_import

import (
	"errors"
	"fmt"
	"os"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/registry/regfile"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run applies a ".reg" file from the local machine to the remote registry (reg.exe
// IMPORT): it creates/updates the keys and values it lists, and honors the delete
// directives "[-Key]" (delete a key and its subtree) and "Name"=- (delete a value).
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	filePath (string): The source .reg file path on the LOCAL machine.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, filePath string, wow64 ndr.DWORD, debug bool) error {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading %q: %s", filePath, err)
	}

	blocks, perr := regfile.Parse(raw)
	if perr != nil {
		// Parsing is best-effort: report the per-line problems but apply what parsed.
		logger.Warn(fmt.Sprintf("parse warnings for %q: %s", filePath, perr))
	}
	if len(blocks) == 0 {
		return fmt.Errorf("no registry keys found in %q", filePath)
	}

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	createdKeys, existingKeys, setValues, deletedKeys, deletedValues := 0, 0, 0, 0, 0
	resultErr := perr
	for _, blk := range blocks {
		if blk.Delete {
			if err := utils.DeleteKeyTreeView(reg, blk.Path, wow64); err != nil {
				if utils.IsNotFound(err) {
					// A delete directive states a desired end state, so a key that is already
					// gone is success rather than a failure (reg.exe behaves the same way).
					continue
				}
				logger.Warn(fmt.Sprintf("error deleting key %q: %s", blk.Path, err))
				resultErr = errors.Join(resultErr, fmt.Errorf("error deleting key %q: %w", blk.Path, err))
				continue
			}
			deletedKeys++
			continue
		}

		if !utils.HasSubkey(blk.Path) {
			logger.Warn(fmt.Sprintf("skipping %q: a value/key cannot be imported into a bare root key", blk.Path))
			resultErr = errors.Join(resultErr, fmt.Errorf("cannot import values or keys into bare root %q", blk.Path))
			continue
		}

		handle, disposition, err := reg.CreateKeyByPath(blk.Path, ms_rrp.KeyWrite|wow64)
		if err != nil {
			logger.Warn(fmt.Sprintf("error creating key %q: %s", blk.Path, err))
			resultErr = errors.Join(resultErr, fmt.Errorf("error creating key %q: %w", blk.Path, err))
			continue
		}
		reg.BaseRegCloseKey(handle)
		if disposition == ms_rrp.RegOpenedExistingKey {
			existingKeys++
		} else {
			createdKeys++
		}

		for _, vl := range blk.Values {
			if vl.Delete {
				if err := utils.DeleteValueView(reg, blk.Path, vl.Name, wow64); err != nil {
					if utils.IsNotFound(err) {
						// Already absent: the directive's end state already holds.
						continue
					}
					logger.Warn(fmt.Sprintf("error deleting value %q in %q: %s", vl.Name, blk.Path, err))
					resultErr = errors.Join(resultErr, fmt.Errorf("error deleting value %q in %q: %w", vl.Name, blk.Path, err))
					continue
				}
				deletedValues++
				continue
			}
			if err := utils.SetValueView(reg, blk.Path, vl.Name, utils.FromRegistryValue(vl.Value), wow64); err != nil {
				logger.Warn(fmt.Sprintf("error setting value %q in %q: %s", vl.Name, blk.Path, err))
				resultErr = errors.Join(resultErr, fmt.Errorf("error setting value %q in %q: %w", vl.Name, blk.Path, err))
				continue
			}
			setValues++
		}
	}

	logger.Print(fmt.Sprintf("[+] Imported \x1b[94m%s\x1b[0m: \x1b[93m%d\x1b[0m keys created, \x1b[93m%d\x1b[0m keys already present, \x1b[93m%d\x1b[0m values set, \x1b[93m%d\x1b[0m keys deleted, \x1b[93m%d\x1b[0m values deleted",
		filePath, createdKeys, existingKeys, setValues, deletedKeys, deletedValues))
	return resultErr
}
