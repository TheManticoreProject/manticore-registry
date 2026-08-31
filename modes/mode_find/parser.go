package mode_find

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/argumentgroup"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "find" subcommand and its argument groups on ap, binding every
// flag to the caller-owned variable it parses into. The Configuration group is returned so the
// caller can tell an explicitly supplied empty pattern (a search for empty names or data) from
// an omitted one.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, pattern *string, exact, contains, caseSensitive *bool, searchKeys, searchValues, searchData *bool, valueType *string, maxDepth, maxResults *int, reg32, reg64 *bool, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) *argumentgroup.ArgumentGroup {
	subparser := ap.AddSubParser("find", "Search a key subtree for matching key names, value names, value data, or value types.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Root of the registry subtree to search (e.g. 'HKLM\\SOFTWARE').")
		group_config.NewStringArgument(pattern, "-f", "--pattern", "", false, "Pattern to look for. Omit to search by --type alone.")
		group_config.NewStringArgument(valueType, "-t", "--type", "", false, "Only consider values of this type (REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_LINK, REG_MULTI_SZ, REG_QWORD, REG_NONE, or a numeric type).")
		group_config.NewBoolArgument(caseSensitive, "-c", "--case-sensitive", false, "Match case-sensitively instead of folding case.")
		group_config.NewIntArgument(maxDepth, "", "--max-depth", 0, false, "Stop recursing below this many levels under the root key (0 for no limit).")
		group_config.NewIntArgument(maxResults, "", "--max-results", 0, false, "Stop the search after this many matches (0 for no limit).")
	}

	group_match, err := subparser.NewNotRequiredMutuallyExclusiveArgumentGroup("Match Mode")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_match.NewBoolArgument(contains, "", "--contains", false, "Match the pattern as a substring. This is the default match mode.")
		group_match.NewBoolArgument(exact, "", "--exact", false, "Match the pattern as a whole string instead of a substring.")
	}

	group_scope, err := subparser.NewArgumentGroup("Search Scope")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_scope.NewBoolArgument(searchKeys, "", "--keys", false, "Match key names. When no scope is selected, key names, value names and value data are all searched.")
		group_scope.NewBoolArgument(searchValues, "", "--values", false, "Match value names. When no scope is selected, key names, value names and value data are all searched.")
		group_scope.NewBoolArgument(searchData, "", "--data", false, "Match value data. When no scope is selected, key names, value names and value data are all searched.")
	}

	cli.RegisterViewGroup(subparser, reg32, reg64)
	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
	return group_config
}
