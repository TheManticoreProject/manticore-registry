package mode_sd

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// Components selects which parts of the security descriptor an operation applies to.
type Components struct {
	Owner bool
	Group bool
	Dacl  bool
	Sacl  bool
}

// Run reads or writes the security descriptor of a remote registry key. When
// sddl is empty it reads the descriptor and prints it as an SDDL string (and, if describe
// is set, a structured breakdown); otherwise it parses the SDDL and applies it.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPath (string): The registry key path (e.g. HKLM\SOFTWARE\Acme).
//	sddl (string): The SDDL to apply; empty to read instead.
//	comp (Components): Which components to operate on (defaults applied when none selected).
//	describe (bool): On read, also print a structured breakdown of the descriptor.
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if the operation fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPath string, sddl string, comp Components, describe bool, wow64 ndr.DWORD, debug bool) error {
	secInfo := securityInformation(comp, sddl == "")

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	samDesired := ms_rrp.MaximumAllowed | wow64
	if secInfo&utils.SecurityInformationSacl != 0 {
		samDesired |= utils.AccessSystemSecurity
	}

	handle, err := reg.OpenKeyByPath(keyPath, samDesired)
	if err != nil {
		return fmt.Errorf("error opening key %q: %s", keyPath, err)
	}
	defer reg.BaseRegCloseKey(handle)

	if sddl == "" {
		return readSecurity(reg, handle, keyPath, secInfo, describe)
	}
	return writeSecurity(reg, handle, keyPath, secInfo, sddl)
}

// readSecurity reads and prints the key's security descriptor.
func readSecurity(reg *ms_rrp.RemoteRegistry, handle ms_rrp.Handle, keyPath string, secInfo ndr.DWORD, describe bool) error {
	raw, err := utils.GetKeySecurity(reg, handle, secInfo)
	if err != nil {
		return fmt.Errorf("error reading security descriptor of %q: %s", keyPath, err)
	}

	var ntsd securitydescriptor.NtSecurityDescriptor
	if _, err := ntsd.Unmarshal(raw); err != nil {
		return fmt.Errorf("error parsing security descriptor of %q: %s", keyPath, err)
	}
	sddl, err := ntsd.ToSDDLString()
	if err != nil {
		return fmt.Errorf("error rendering SDDL for %q: %s", keyPath, err)
	}

	logger.Print(fmt.Sprintf("[>] \x1b[94m%s\x1b[0m", keyPath))
	logger.Print(fmt.Sprintf("    SDDL: %s", sddl))
	if describe {
		ntsd.Describe(1)
	}
	return nil
}

// writeSecurity parses an SDDL string and applies it to the key.
func writeSecurity(reg *ms_rrp.RemoteRegistry, handle ms_rrp.Handle, keyPath string, secInfo ndr.DWORD, sddl string) error {
	var ntsd securitydescriptor.NtSecurityDescriptor
	if _, err := ntsd.FromSDDLString(sddl); err != nil {
		return fmt.Errorf("error parsing SDDL %q: %s", sddl, err)
	}
	raw, err := ntsd.Marshal()
	if err != nil {
		return fmt.Errorf("error marshalling security descriptor: %s", err)
	}
	if err := utils.SetKeySecurity(reg, handle, secInfo, raw); err != nil {
		return fmt.Errorf("error setting security descriptor on %q: %s", keyPath, err)
	}

	logger.Print(fmt.Sprintf("[+] Set security descriptor on \x1b[94m%s\x1b[0m", keyPath))
	return nil
}

// securityInformation builds the SECURITY_INFORMATION mask from the selected components.
// When none are selected, the default is owner+group+DACL for a read and DACL-only for a
// write (the SACL is only ever included when explicitly requested).
func securityInformation(comp Components, reading bool) ndr.DWORD {
	if !comp.Owner && !comp.Group && !comp.Dacl && !comp.Sacl {
		if reading {
			return utils.SecurityInformationOwner | utils.SecurityInformationGroup | utils.SecurityInformationDacl
		}
		return utils.SecurityInformationDacl
	}
	var mask ndr.DWORD
	if comp.Owner {
		mask |= utils.SecurityInformationOwner
	}
	if comp.Group {
		mask |= utils.SecurityInformationGroup
	}
	if comp.Dacl {
		mask |= utils.SecurityInformationDacl
	}
	if comp.Sacl {
		mask |= utils.SecurityInformationSacl
	}
	return mask
}
