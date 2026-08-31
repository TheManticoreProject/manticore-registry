package mode_add

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/argumentgroup"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "add" subcommand and its argument groups on ap, binding every
// flag to the caller-owned variable it parses into. The value-type flags form a non-required
// mutually exclusive group.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, valueName *string, valSz, valExpandSz, valDword, valQword, valBinary, valMultiSz *string, reg32, reg64 *bool, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) *argumentgroup.ArgumentGroup {
	subparser := ap.AddSubParser("add", "Add (create) a key, or set a typed value, on a remote machine.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Registry key path to create or write to (e.g. 'HKCU\\Software\\Acme').")
		group_config.NewStringArgument(valueName, "-v", "--value", "", false, "Value name to set. If omitted with no value-type flag, only the key is created.")
	}

	group_value, err := subparser.NewNotRequiredMutuallyExclusiveArgumentGroup("Value")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_value.NewStringArgument(valSz, "", "--sz", "", false, "Set a REG_SZ (string) value.")
		group_value.NewStringArgument(valExpandSz, "", "--expand-sz", "", false, "Set a REG_EXPAND_SZ (expandable string) value.")
		group_value.NewStringArgument(valDword, "", "--dword", "", false, "Set a REG_DWORD value (decimal or 0x-prefixed hex).")
		group_value.NewStringArgument(valQword, "", "--qword", "", false, "Set a REG_QWORD value (decimal or 0x-prefixed hex).")
		group_value.NewStringArgument(valBinary, "", "--binary", "", false, "Set a REG_BINARY value (hex-encoded bytes, e.g. 'deadbeef').")
		group_value.NewStringArgument(valMultiSz, "", "--multi-sz", "", false, "Set a REG_MULTI_SZ value (comma-separated items).")
	}

	cli.RegisterViewGroup(subparser, reg32, reg64)
	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
	return group_value
}
