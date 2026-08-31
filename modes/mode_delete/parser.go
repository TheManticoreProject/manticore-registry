package mode_delete

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/argumentgroup"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "delete" subcommand and its argument groups on ap, binding
// every flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, valueName *string, recurse, allValues, force *bool, reg32, reg64 *bool, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) *argumentgroup.ArgumentGroup {
	subparser := ap.AddSubParser("delete", "Delete a value, or a leaf key, on a remote machine.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Registry key path (e.g. 'HKCU\\Software\\Acme').")
		group_config.NewStringArgument(valueName, "-v", "--value", "", false, "Value name to delete. If omitted, the key itself is deleted.")
		group_config.NewBoolArgument(recurse, "-r", "--recurse", false, "Delete the key together with all its subkeys.")
		group_config.NewBoolArgument(allValues, "", "--all-values", false, "Delete all values under the key, keeping the key and its subkeys.")
		group_config.NewBoolArgument(force, "-f", "--force", false, "Delete without prompting for confirmation.")
	}

	cli.RegisterViewGroup(subparser, reg32, reg64)
	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
	return group_config
}
