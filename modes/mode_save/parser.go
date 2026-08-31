package mode_save

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "save" subcommand and its argument groups on ap, binding every
// flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, filePath *string, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) {
	subparser := ap.AddSubParser("save", "Save a key and its subtree to a hive file on the remote machine.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Registry key path to save (e.g. 'HKLM\\SOFTWARE\\Acme').")
		group_config.NewStringArgument(filePath, "-f", "--file", "", true, "Destination hive file path on the remote machine (e.g. 'C:\\Windows\\Temp\\acme.hiv').")
	}

	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
}
