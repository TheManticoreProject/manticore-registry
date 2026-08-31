package mode_export

import (
	"fmt"
	"os"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/registry/regfile"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run recursively exports a registry key and its subtree from the remote machine to a
// ".reg" file on the local machine (reg.exe EXPORT). The file is written in the regedit
// version-5 format (UTF-16LE with BOM, CRLF line endings).
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path to export (e.g. HKLM\SOFTWARE\Acme).
//	filePath (string): The destination .reg file path on the LOCAL machine.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, filePath string, wow64 ndr.DWORD, debug bool) error {
	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	var blocks []regfile.KeyBlock
	values, err := collectBlocks(reg, keyPath, wow64, &blocks)
	if err != nil {
		return fmt.Errorf("export aborted before writing %q: %w", filePath, err)
	}

	if err := os.WriteFile(filePath, regfile.Marshal(blocks), 0o600); err != nil {
		return fmt.Errorf("error writing %q: %s", filePath, err)
	}

	logger.Print(fmt.Sprintf("[+] Exported \x1b[94m%s\x1b[0m to \x1b[94m%s\x1b[0m (\x1b[93m%d\x1b[0m keys, \x1b[93m%d\x1b[0m values)", keyPath, filePath, len(blocks), values))
	return nil
}

// collectBlocks walks keyPath depth-first, appending a regfile.KeyBlock per key, and
// returns the total number of values collected. Any unreadable key aborts collection, so
// Run never replaces the destination with an incomplete backup.
func collectBlocks(reg *ms_rrp.RemoteRegistry, keyPath string, wow64 ndr.DWORD, blocks *[]regfile.KeyBlock) (int, error) {
	entries, err := utils.EnumValuesView(reg, keyPath, wow64)
	if err != nil {
		return 0, fmt.Errorf("error reading values of %q: %w", keyPath, err)
	}

	block := regfile.KeyBlock{Path: utils.ExpandRootLong(keyPath)}
	for _, e := range entries {
		block.Values = append(block.Values, regfile.ValueLine{Name: e.Name, Value: utils.ToRegistryValue(e.Value)})
	}
	*blocks = append(*blocks, block)
	total := len(entries)

	subkeys, err := utils.EnumKeysView(reg, keyPath, wow64)
	if err != nil {
		return 0, fmt.Errorf("error reading subkeys of %q: %w", keyPath, err)
	}
	for _, name := range subkeys {
		count, err := collectBlocks(reg, keyPath+`\`+name, wow64, blocks)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}
