// Package cli holds argument groups shared by every mode's parser.go. The SMB Connection,
// Authentication and Registry View groups are identical across the subcommands, so they are
// registered through these helpers rather than duplicated in each SetupSubParser.
package cli

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/goopts/parser"
)

// RegisterConnectionAndAuthGroups adds the SMB Connection Settings and Authentication argument
// groups to a subparser, binding each flag to the caller-owned variable it parses into. goopts
// delegates parsing entirely to the matched subparser, so these shared flags must be registered
// on each one.
func RegisterConnectionAndAuthGroups(subparser *parser.ArgumentsParser, host *string, port *int, authDomain, authUsername, authPassword, authHashes *string) {
	group_connection, err := subparser.NewArgumentGroup("SMB Connection Settings")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_connection.NewStringArgument(host, "", "--host", "", true, "Hostname or IP address of the target machine.")
		group_connection.NewTcpPortArgument(port, "", "--port", 445, false, "SMB port to connect to on the target machine.")
	}

	group_auth, err := subparser.NewArgumentGroup("Authentication")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_auth.NewStringArgument(authDomain, "-d", "--domain", "", false, "Active Directory domain to authenticate to.")
		group_auth.NewStringArgument(authUsername, "-u", "--username", "", true, "User to authenticate as.")
		group_auth.NewStringArgument(authPassword, "-p", "--password", "", false, "Password to authenticate with.")
		group_auth.NewStringArgument(authHashes, "-H", "--hashes", "", false, "NT/LM hashes, format is LMhash:NThash.")
	}
}

// RegisterViewGroup adds a mutually exclusive Registry View group (--reg32 / --reg64) to a
// subparser, selecting the WOW64 view to operate in.
func RegisterViewGroup(subparser *parser.ArgumentsParser, reg32, reg64 *bool) {
	group_view, err := subparser.NewNotRequiredMutuallyExclusiveArgumentGroup("Registry View")
	if err != nil {
		logger.Warn(fmt.Sprintf("Error creating ArgumentGroup: %s", err))
	} else {
		group_view.NewBoolArgument(reg32, "", "--reg32", false, "Operate on the 32-bit (WOW64) registry view.")
		group_view.NewBoolArgument(reg64, "", "--reg64", false, "Operate on the 64-bit registry view.")
	}
}
