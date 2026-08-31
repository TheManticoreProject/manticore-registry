package mode_sd

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "sd" subcommand and its argument groups on ap, binding every
// flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPath, sddl *string, describe, sdOwner, sdGroup, sdDacl, sdSacl *bool, reg32, reg64 *bool, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) {
	subparser := ap.AddSubParser("sd", "Read or set the security descriptor (owner/group/DACL/SACL) of a key, as SDDL.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewStringArgument(keyPath, "-k", "--key", "", true, "Registry key path (e.g. 'HKLM\\SOFTWARE\\Acme').")
		group_config.NewStringArgument(sddl, "-s", "--sddl", "", false, "SDDL string to apply. If omitted, the current descriptor is read and printed.")
		group_config.NewBoolArgument(describe, "", "--describe", false, "On read, also print a structured breakdown of the descriptor.")
	}

	group_components, err := subparser.NewArgumentGroup("Components")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_components.NewBoolArgument(sdOwner, "", "--owner", false, "Operate on the owner. (read default: owner+group+DACL; write default: DACL)")
		group_components.NewBoolArgument(sdGroup, "", "--group", false, "Operate on the group.")
		group_components.NewBoolArgument(sdDacl, "", "--dacl", false, "Operate on the DACL.")
		group_components.NewBoolArgument(sdSacl, "", "--sacl", false, "Operate on the SACL (requires SeSecurityPrivilege).")
	}

	cli.RegisterViewGroup(subparser, reg32, reg64)
	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
}
