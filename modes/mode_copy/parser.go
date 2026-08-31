package mode_copy

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "copy" subcommand and its argument groups on ap, binding every
// flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, targetKey *string, reg32, reg64 *bool, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) {
	subparser := ap.AddSubParser("copy", "Recursively copy a key (values and subkeys) to another key on the same machine.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Source registry key path (e.g. 'HKLM\\SOFTWARE\\Acme').")
		group_config.NewStringArgument(targetKey, "-t", "--target", "", true, "Destination registry key path (e.g. 'HKLM\\SOFTWARE\\AcmeBackup').")
	}

	cli.RegisterViewGroup(subparser, reg32, reg64)
	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
}
