package mode_monitor

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
	"github.com/TheManticoreProject/manticore-registry/cli"
)

// SetupSubParser registers the "monitor" subcommand and its argument groups on ap, binding
// every flag to the caller-owned variable it parses into.
func SetupSubParser(ap *parser.ArgumentsParser, debug *bool, keyPaths *[]string, interval *int, monitorSacl *bool, reg32, reg64 *bool, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) {
	subparser := ap.AddSubParser("monitor", "Watch a key subtree on a refresh loop and report created/deleted keys, changed values, and ACL changes.")
	subparser.NewBoolArgument(debug, "", "--debug", false, "Enable debug mode.")

	group_config, err := subparser.NewArgumentGroup("Configuration")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_config.NewListOfStringsArgument(keyPaths, "-k", "--key", nil, true, "Root of a registry subtree to monitor. Repeat to watch several (e.g. -k 'HKLM\\SOFTWARE\\Acme' -k 'HKCU\\Software\\Acme').")
		group_config.NewIntArgument(interval, "-i", "--interval", 5, false, "Seconds between subtree snapshots.")
		group_config.NewBoolArgument(monitorSacl, "", "--sacl", false, "Also watch the SACL of each key (requires SeSecurityPrivilege).")
	}

	cli.RegisterViewGroup(subparser, reg32, reg64)
	cli.RegisterConnectionAndAuthGroups(subparser, host, port, authDomain, authUsername, authPassword, authHashes)
}
