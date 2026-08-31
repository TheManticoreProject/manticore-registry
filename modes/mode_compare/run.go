package mode_compare

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// Run recursively compares two registry keys on the same remote machine, reporting
// values and subkeys that differ between them (reg.exe COMPARE semantics). It prints each
// difference and a final summary.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	pathA (string): The first registry key path.
//	pathB (string): The second registry key path.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply to both keys (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, pathA string, pathB string, wow64 ndr.DWORD, debug bool) error {
	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	logger.Print(fmt.Sprintf("[>] Comparing \x1b[94m%s\x1b[0m (A) and \x1b[94m%s\x1b[0m (B)", pathA, pathB))
	diffs, incomplete := compareRecursive(reg, pathA, pathB, wow64)
	switch {
	case diffs == 0 && !incomplete:
		logger.Print("[>] The two keys are identical.")
	case diffs == 0 && incomplete:
		logger.Print("[>] No differences found, but some keys were inaccessible, so the comparison is incomplete.")
	case incomplete:
		logger.Print(fmt.Sprintf("[>] \x1b[93m%d\x1b[0m difference(s) found; some keys were inaccessible, so the comparison is incomplete.", diffs))
	default:
		logger.Print(fmt.Sprintf("[>] \x1b[93m%d\x1b[0m difference(s) found.", diffs))
	}
	if incomplete {
		return fmt.Errorf("comparison incomplete because one or more keys were inaccessible")
	}
	return nil
}

// compareRecursive compares one key level and recurses into shared subkeys, returning the
// number of differences found and whether the comparison was incomplete. A key whose values
// or subkeys cannot be read on either side is reported as a warning and that part is skipped
// (incomplete = true) rather than aborting the whole comparison; values/subkeys are only
// diffed when both sides could be read, so an unreadable side is never miscounted as a diff.
func compareRecursive(reg *ms_rrp.RemoteRegistry, pathA, pathB string, wow64 ndr.DWORD) (diffs int, incomplete bool) {
	valsA, errA := utils.EnumValuesView(reg, pathA, wow64)
	if errA != nil {
		logger.Warn(fmt.Sprintf("error reading values of %q: %s", pathA, errA))
		incomplete = true
	}
	valsB, errB := utils.EnumValuesView(reg, pathB, wow64)
	if errB != nil {
		logger.Warn(fmt.Sprintf("error reading values of %q: %s", pathB, errB))
		incomplete = true
	}
	if errA == nil && errB == nil {
		mapB := indexValues(valsB)
		seen := make(map[string]bool, len(valsA))
		for _, e := range valsA {
			foldedName := strings.ToLower(e.Name)
			seen[foldedName] = true
			bVal, ok := mapB[foldedName]
			switch {
			case !ok:
				logger.Print(fmt.Sprintf("    \x1b[91m- only in A\x1b[0m  %s\\%s = %s", pathA, utils.DisplayValueName(e.Name), utils.FormatValue(e.Value)))
				diffs++
			case e.Value.Type != bVal.Type || !bytes.Equal(e.Value.Data, bVal.Data):
				logger.Print(fmt.Sprintf("    \x1b[93m~ differs\x1b[0m   %s\\%s : A=%s (%s)  B=%s (%s)", pathA, utils.DisplayValueName(e.Name),
					utils.FormatValue(e.Value), utils.TypeName(e.Value.Type), utils.FormatValue(bVal), utils.TypeName(bVal.Type)))
				diffs++
			}
		}
		for _, e := range valsB {
			if !seen[strings.ToLower(e.Name)] {
				logger.Print(fmt.Sprintf("    \x1b[92m+ only in B\x1b[0m  %s\\%s = %s", pathB, utils.DisplayValueName(e.Name), utils.FormatValue(e.Value)))
				diffs++
			}
		}
	}

	// Subkeys.
	subsA, errA := utils.EnumKeysView(reg, pathA, wow64)
	if errA != nil {
		logger.Warn(fmt.Sprintf("error reading subkeys of %q: %s", pathA, errA))
		incomplete = true
	}
	subsB, errB := utils.EnumKeysView(reg, pathB, wow64)
	if errB != nil {
		logger.Warn(fmt.Sprintf("error reading subkeys of %q: %s", pathB, errB))
		incomplete = true
	}
	if errA != nil || errB != nil {
		return diffs, incomplete
	}

	setB := indexSubkeys(subsB)
	setA := indexSubkeys(subsA)
	for _, s := range subsA {
		counterpart, ok := setB[strings.ToLower(s)]
		if !ok {
			logger.Print(fmt.Sprintf("    \x1b[91m- only in A\x1b[0m  %s\\%s\\ (subkey)", pathA, s))
			diffs++
			continue
		}
		// Present in both: recurse.
		d, inc := compareRecursive(reg, pathA+`\`+s, pathB+`\`+counterpart, wow64)
		diffs += d
		if inc {
			incomplete = true
		}
	}
	for _, s := range subsB {
		if _, ok := setA[strings.ToLower(s)]; !ok {
			logger.Print(fmt.Sprintf("    \x1b[92m+ only in B\x1b[0m  %s\\%s\\ (subkey)", pathB, s))
			diffs++
		}
	}

	return diffs, incomplete
}

// indexValues and indexSubkeys use the registry's case-insensitive name semantics while
// retaining the server-returned subkey spelling for paths used in subsequent RPC calls.
func indexValues(entries []ms_rrp.ValueEntry) map[string]ms_rrp.RegistryValue {
	indexed := make(map[string]ms_rrp.RegistryValue, len(entries))
	for _, entry := range entries {
		indexed[strings.ToLower(entry.Name)] = entry.Value
	}
	return indexed
}

func indexSubkeys(names []string) map[string]string {
	indexed := make(map[string]string, len(names))
	for _, name := range names {
		indexed[strings.ToLower(name)] = name
	}
	return indexed
}
