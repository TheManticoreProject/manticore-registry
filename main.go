package main

import (
	"fmt"
	"os"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_add"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_compare"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_copy"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_delete"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_export"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_find"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_import"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_load"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_monitor"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_query"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_restore"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_save"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_sd"
	"github.com/TheManticoreProject/manticore-registry/modes/mode_unload"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

var (
	mode string

	// Configuration
	debug bool

	// Registry target
	keyPath           string
	valueName         string
	valueNameProvided bool
	force             bool

	// Second key path (copy destination / compare counterpart)
	targetKey string

	// Security descriptor (sd mode)
	sddl       string
	sdOwner    bool
	sdGroup    bool
	sdDacl     bool
	sdSacl     bool
	sdDescribe bool

	// Behavioral flags
	recurse   bool // query -s / delete -r: operate on the whole subtree
	allValues bool // delete --all-values: delete every value under the key

	// query search (-f)
	querySearchPattern string
	querySearchKeys    bool
	querySearchValues  bool
	querySearchData    bool

	// find mode
	findPattern         string
	findPatternProvided bool
	findExact           bool
	findContains        bool
	findCaseSensitive   bool
	findKeys            bool
	findValues          bool
	findData            bool
	findType            string
	findMaxDepth        int
	findMaxResults      int

	// monitor mode
	monitorKeys     []string
	monitorInterval int
	monitorSacl     bool

	// WOW64 registry view selection
	reg32 bool
	reg64 bool

	// Hive maintenance (save/restore/load): file path on the remote machine
	filePath string

	// Value-type subflags (add mode, mutually exclusive)
	valSz               string
	valSzProvided       bool
	valExpandSz         string
	valExpandSzProvided bool
	valDword            string
	valDwordProvided    bool
	valQword            string
	valQwordProvided    bool
	valBinary           string
	valBinaryProvided   bool
	valMultiSz          string
	valMultiSzProvided  bool

	// SMB Connection Settings
	host string
	port int

	// Authentication
	authDomain   string
	authUsername string
	authPassword string
	authHashes   string
)

func parseArgs() {
	ap := parser.ArgumentsParser{
		Banner: "manticore-registry - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0",
	}
	ap.SetupSubParsing("mode", &mode, true)
	ap.SetOptShowBannerOnHelp(true)
	ap.SetOptShowBannerOnRun(true)

	queryConfig := mode_query.SetupSubParser(&ap, &debug, &keyPath, &valueName, &recurse, &querySearchPattern, &querySearchKeys, &querySearchValues, &querySearchData, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	addValues := mode_add.SetupSubParser(&ap, &debug, &keyPath, &valueName, &valSz, &valExpandSz, &valDword, &valQword, &valBinary, &valMultiSz, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	findConfig := mode_find.SetupSubParser(&ap, &debug, &keyPath, &findPattern, &findExact, &findContains, &findCaseSensitive, &findKeys, &findValues, &findData, &findType, &findMaxDepth, &findMaxResults, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	deleteConfig := mode_delete.SetupSubParser(&ap, &debug, &keyPath, &valueName, &recurse, &allValues, &force, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_save.SetupSubParser(&ap, &debug, &keyPath, &filePath, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_restore.SetupSubParser(&ap, &debug, &keyPath, &filePath, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_load.SetupSubParser(&ap, &debug, &keyPath, &filePath, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_unload.SetupSubParser(&ap, &debug, &keyPath, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_copy.SetupSubParser(&ap, &debug, &keyPath, &targetKey, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_compare.SetupSubParser(&ap, &debug, &keyPath, &targetKey, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_export.SetupSubParser(&ap, &debug, &keyPath, &filePath, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_import.SetupSubParser(&ap, &debug, &filePath, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_sd.SetupSubParser(&ap, &debug, &keyPath, &sddl, &sdDescribe, &sdOwner, &sdGroup, &sdDacl, &sdSacl, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)
	mode_monitor.SetupSubParser(&ap, &debug, &monitorKeys, &monitorInterval, &monitorSacl, &reg32, &reg64, &host, &port, &authDomain, &authUsername, &authPassword, &authHashes)

	ap.Parse()

	switch mode {
	case "query":
		valueNameProvided = queryConfig != nil && queryConfig.ArgumentIsPresent("--value")
	case "find":
		findPatternProvided = findConfig != nil && findConfig.ArgumentIsPresent("--pattern")
	case "delete":
		valueNameProvided = deleteConfig != nil && deleteConfig.ArgumentIsPresent("--value")
	case "add":
		if addValues != nil {
			valSzProvided = addValues.ArgumentIsPresent("--sz")
			valExpandSzProvided = addValues.ArgumentIsPresent("--expand-sz")
			valDwordProvided = addValues.ArgumentIsPresent("--dword")
			valQwordProvided = addValues.ArgumentIsPresent("--qword")
			valBinaryProvided = addValues.ArgumentIsPresent("--binary")
			valMultiSzProvided = addValues.ArgumentIsPresent("--multi-sz")
		}
	}
}

func run() error {
	parseArgs()

	creds, err := credentials.NewCredentials(authDomain, authUsername, authPassword, authHashes)
	if err != nil {
		return fmt.Errorf("error creating credentials: %w", err)
	}

	wow64 := utils.Wow64View(reg32, reg64)

	switch mode {
	case "query":
		err = mode_query.RunWithValuePresence(host, port, creds, keyPath, valueName, valueNameProvided, recurse, querySearchPattern, querySearchKeys, querySearchValues, querySearchData, wow64, debug)

	case "find":
		opts := mode_find.Options{
			Pattern:         findPattern,
			PatternProvided: findPatternProvided,
			Exact:           findExact,
			CaseSensitive:   findCaseSensitive,
			Keys:            findKeys,
			Values:          findValues,
			Data:            findData,
			Type:            findType,
			MaxDepth:        findMaxDepth,
			MaxResults:      findMaxResults,
		}
		err = mode_find.Run(host, port, creds, keyPath, opts, wow64, debug)

	case "add":
		flags := utils.ValueTypeFlags{
			Sz:         valSz,
			SzIs:       valSzProvided,
			ExpandSz:   valExpandSz,
			ExpandSzIs: valExpandSzProvided,
			Dword:      valDword,
			DwordIs:    valDwordProvided,
			Qword:      valQword,
			QwordIs:    valQwordProvided,
			Binary:     valBinary,
			BinaryIs:   valBinaryProvided,
			MultiSz:    valMultiSz,
			MultiSzIs:  valMultiSzProvided,
		}
		err = mode_add.Run(host, port, creds, keyPath, valueName, flags, wow64, debug)

	case "delete":
		err = mode_delete.RunWithValuePresence(host, port, creds, keyPath, valueName, valueNameProvided, recurse, allValues, force, wow64, debug)

	case "save":
		err = mode_save.Run(host, port, creds, keyPath, filePath, debug)

	case "restore":
		err = mode_restore.Run(host, port, creds, keyPath, filePath, debug)

	case "load":
		err = mode_load.Run(host, port, creds, keyPath, filePath, debug)

	case "unload":
		err = mode_unload.Run(host, port, creds, keyPath, debug)

	case "copy":
		err = mode_copy.Run(host, port, creds, keyPath, targetKey, wow64, debug)

	case "compare":
		err = mode_compare.Run(host, port, creds, keyPath, targetKey, wow64, debug)

	case "export":
		err = mode_export.Run(host, port, creds, keyPath, filePath, wow64, debug)

	case "import":
		err = mode_import.Run(host, port, creds, filePath, wow64, debug)

	case "sd":
		comp := mode_sd.Components{Owner: sdOwner, Group: sdGroup, Dacl: sdDacl, Sacl: sdSacl}
		err = mode_sd.Run(host, port, creds, keyPath, sddl, comp, sdDescribe, wow64, debug)

	case "monitor":
		err = mode_monitor.Run(host, port, creds, monitorKeys, monitorInterval, monitorSacl, wow64, debug)

	default:
		return fmt.Errorf("invalid mode %q", mode)
	}

	if err != nil {
		return fmt.Errorf("error running %s mode: %w", mode, err)
	}

	logger.Print("Done.")
	return nil
}

func main() {
	if err := run(); err != nil {
		logger.Warn(err.Error())
		os.Exit(1)
	}
}
