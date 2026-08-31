package mode_load

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "load" subcommand and its argument groups on ap, binding every
// flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, filePath *string, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) {
	subparser := ap.AddSubParser("load", "Load a hive file on the remote machine as a new subkey under HKLM or HKU.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Mount point for the hive (e.g. 'HKLM\\TempHive'). Its leaf subkey is created by the load.")
		group_config.NewStringArgument(filePath, "-f", "--file", "", true, "Source hive file path on the remote machine.")
	}

	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
}
