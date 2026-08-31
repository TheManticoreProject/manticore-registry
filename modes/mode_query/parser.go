package mode_query

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/argumentgroup"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "query" subcommand and its argument groups on ap, binding every
// flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, valueName *string, recurse *bool, findPattern *string, searchKeys, searchValues, searchData *bool, reg32, reg64 *bool, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) *argumentgroup.ArgumentGroup {
	subparser := ap.AddSubParser("query", "Query a value, or enumerate the subkeys and values of a key, on a remote machine.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Registry key path (e.g. 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').")
		group_config.NewStringArgument(valueName, "-v", "--value", "", false, "Value name to read. If omitted, the key's subkeys and values are enumerated.")
		group_config.NewBoolArgument(recurse, "-s", "--recurse", false, "Recurse into all subkeys (whole-subtree dump, or recursive search with --find).")
		group_config.NewStringArgument(findPattern, "-f", "--find", "", false, "Recursively search the subtree for a case-insensitive substring.")
		group_config.NewBoolArgument(searchKeys, "", "--keys", false, "With --find: match subkey names. (default: keys, values and data)")
		group_config.NewBoolArgument(searchValues, "", "--values", false, "With --find: match value names. (default: keys, values and data)")
		group_config.NewBoolArgument(searchData, "", "--data", false, "With --find: match value data. (default: keys, values and data)")
	}

	cli.RegisterViewGroup(subparser, reg32, reg64)
	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
	return group_config
}
