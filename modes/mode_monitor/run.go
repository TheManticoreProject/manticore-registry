// Package mode_monitor implements the "monitor" mode: it watches one or more registry subtrees
// on a refresh loop and reports the keys, values and security descriptors (ACLs) that change as
// they change, the way a live registry watcher does. The starting state is the baseline and
// is not printed; only subsequent changes are reported, each with a timestamp. Ctrl-C stops
// the loop cleanly.
//
// MS-RRP exposes no usable change-notification primitive here, so the mode polls: it walks
// the whole subtree each interval and diffs the new snapshot against the previous one. Unlike
// a signal-only notification, a diff can report exactly what changed, including the new value
// data and the new SDDL.
package mode_monitor

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/TheManticoreProject/Manticore/logger"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/manticore-registry/utils"
)

// monitoredValue is one value as recorded in a snapshot: the name as the server spelled it,
// kept for display, plus its data.
type monitoredValue struct {
	name  string
	value ms_rrp.RegistryValue
}

// keyState is the monitored state of a single key: its values and its security descriptor
// rendered as SDDL. The SDDL string is compared directly to detect ACL changes, which keeps
// the diff independent of the on-the-wire byte ordering of the descriptor. Values are indexed
// by their folded name because registry value names are case-insensitive, so a value renamed
// only in case reads as one change rather than a delete plus a create. path is the key path as
// the walk reached it, used for display.
type keyState struct {
	path   string
	values map[string]monitoredValue
	sddl   string
}

// snapshot maps the canonical form of every key path in the monitored subtrees (see
// utils.CanonicalKeyPath) to its keyState. Canonical keys mean the same registry key reached
// through two spellings of a watched root, or through a root that encloses another, is
// recorded once instead of being diffed against itself.
type snapshot map[string]keyState

// Run watches one or more subtrees on a remote machine and reports created and deleted
// keys, created/deleted/changed values, and security-descriptor changes every interval seconds
// until interrupted with Ctrl-C. The baseline subtrees are not printed; only subsequent changes
// are reported. The subtrees are diffed together as a single key set, so a key moving between
// two watched trees reads as one delete and one create.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	keyPaths ([]string): The roots of the subtrees to monitor (e.g. HKLM\SOFTWARE\Acme).
//	interval (int): Seconds between snapshots (minimum 1).
//	monitorSacl (bool): Also watch the SACL (requires SeSecurityPrivilege).
//	wow64 (ndr.DWORD): The WOW64 view SAM bit to apply (0 for the default view).
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	An error if no subtree is given, or if the connection or baseline snapshot fails, nil otherwise.
func Run(host string, port int, creds *credentials.Credentials, keyPaths []string, interval int, monitorSacl bool, wow64 ndr.DWORD, debug bool) error {
	if len(keyPaths) == 0 {
		return fmt.Errorf("no subtree to monitor was given")
	}
	if interval < 1 {
		interval = 1
	}
	period := time.Duration(interval) * time.Second
	secInfo := securityInformation(monitorSacl)

	reg, cleanup, err := utils.ConnectRegistry(host, port, creds, debug)
	if err != nil {
		return err
	}
	defer cleanup()

	// Baseline snapshot: everything already present is the starting state, so only subsequent
	// changes are reported. A failure here is fatal: there is nothing to diff against.
	before, err := takeSnapshot(reg, keyPaths, secInfo, wow64)
	if err != nil {
		return fmt.Errorf("error taking baseline snapshot: %s", err)
	}

	logger.Print(fmt.Sprintf("[>] Monitoring \x1b[94m%s\x1b[0m on %s every %ds (baseline: %d keys). Press Ctrl-C to stop.", strings.Join(keyPaths, "\x1b[0m, \x1b[94m"), host, interval, len(before)))

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			logger.Print("[>] Stopping monitor.")
			return nil

		case <-ticker.C:
			now, err := takeSnapshot(reg, keyPaths, secInfo, wow64)
			if err != nil {
				// A transient failure (e.g. the root key briefly went away) should not end the
				// monitor; warn and keep the previous baseline so the next tick can recover.
				logger.Warn(fmt.Sprintf("Snapshot failed, keeping previous state: %s", err))
				continue
			}
			reportChanges(before, now)
			before = now
		}
	}
}

// securityInformation builds the SECURITY_INFORMATION mask the monitor reads each snapshot:
// owner+group+DACL always, plus the SACL when explicitly requested (it needs a privilege the
// other components do not).
func securityInformation(monitorSacl bool) ndr.DWORD {
	mask := utils.SecurityInformationOwner | utils.SecurityInformationGroup | utils.SecurityInformationDacl
	if monitorSacl {
		mask |= utils.SecurityInformationSacl
	}
	return mask
}

// takeSnapshot walks each subtree in keyPaths depth-first and records every key's values and
// SDDL into a single snapshot. A key whose values, subkeys or security descriptor cannot be
// read is reported as a warning and skipped (its parts left empty) rather than aborting the
// whole snapshot, mirroring the tolerance of the "compare" mode; the walk still fails outright
// only if one of the requested root keys cannot be opened, which the caller surfaces. Overlapping
// subtrees are recorded once, whatever spelling each root was given in.
func takeSnapshot(reg *ms_rrp.RemoteRegistry, keyPaths []string, secInfo ndr.DWORD, wow64 ndr.DWORD) (snapshot, error) {
	snap := make(snapshot)
	for _, keyPath := range keyPaths {
		if err := walkSnapshot(reg, keyPath, secInfo, wow64, snap, true); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

// walkSnapshot records one key into snap and recurses into its subkeys. isRoot distinguishes
// the user-supplied root (whose failure to enumerate aborts the snapshot) from descendant keys
// (whose individual failures are warnings that do not abort the walk).
func walkSnapshot(reg *ms_rrp.RemoteRegistry, keyPath string, secInfo ndr.DWORD, wow64 ndr.DWORD, snap snapshot, isRoot bool) error {
	canonical := utils.CanonicalKeyPath(keyPath)
	if _, ok := snap[canonical]; ok {
		// Already recorded through another watched root, however that root was spelled.
		return nil
	}

	st := keyState{path: keyPath, values: make(map[string]monitoredValue)}

	values, err := utils.EnumValuesView(reg, keyPath, wow64)
	if err != nil {
		if isRoot {
			return fmt.Errorf("error reading values of %q: %s", keyPath, err)
		}
		logger.Warn(fmt.Sprintf("error reading values of %q: %s", keyPath, err))
	}
	for _, e := range values {
		st.values[strings.ToLower(e.Name)] = monitoredValue{name: e.Name, value: e.Value}
	}

	if sddl, err := utils.ReadKeySDDLView(reg, keyPath, secInfo, wow64); err != nil {
		logger.Warn(fmt.Sprintf("error reading security descriptor of %q: %s", keyPath, err))
	} else {
		st.sddl = sddl
	}

	snap[canonical] = st

	subkeys, err := utils.EnumKeysView(reg, keyPath, wow64)
	if err != nil {
		if isRoot {
			return fmt.Errorf("error reading subkeys of %q: %s", keyPath, err)
		}
		logger.Warn(fmt.Sprintf("error reading subkeys of %q: %s", keyPath, err))
		return nil
	}
	for _, name := range subkeys {
		// A descendant failure is already swallowed inside the recursive call, so the returned
		// error is only ever non-nil for the root; descendants always return nil here.
		_ = walkSnapshot(reg, keyPath+`\`+name, secInfo, wow64, snap, false)
	}
	return nil
}

// reportChanges diffs two snapshots and prints, with the logger's timestamp prefix, the keys,
// values and security descriptors that changed between them. Deletions are printed before
// creations so that a key move reads delete-then-create. Unchanged state is not printed.
func reportChanges(before, now snapshot) {
	deletedKeys, createdKeys := diffKeys(before, now)

	for _, k := range deletedKeys {
		logger.Print(fmt.Sprintf("Key \x1b[1;91mdeleted\x1b[0m: \x1b[94m%s\x1b[0m", before[k].path))
	}
	for _, k := range createdKeys {
		logger.Print(fmt.Sprintf("Key \x1b[1;92mcreated\x1b[0m: \x1b[94m%s\x1b[0m", now[k].path))
	}

	// Keys present in both snapshots: report value and security-descriptor changes. Iterate in
	// sorted order for deterministic output.
	for _, k := range sortedCommonKeys(before, now) {
		reportValueChanges(now[k].path, before[k], now[k])
		reportSecurityChange(now[k].path, before[k], now[k])
	}
}

// diffKeys returns the key paths that disappeared (deleted) and appeared (created) between two
// snapshots, each sorted for deterministic output.
func diffKeys(before, now snapshot) (deleted, created []string) {
	for k := range before {
		if _, ok := now[k]; !ok {
			deleted = append(deleted, k)
		}
	}
	for k := range now {
		if _, ok := before[k]; !ok {
			created = append(created, k)
		}
	}
	sort.Strings(deleted)
	sort.Strings(created)
	return deleted, created
}

// sortedCommonKeys returns the key paths present in both snapshots, sorted.
func sortedCommonKeys(before, now snapshot) []string {
	common := make([]string, 0, len(now))
	for k := range now {
		if _, ok := before[k]; ok {
			common = append(common, k)
		}
	}
	sort.Strings(common)
	return common
}

// reportValueChanges prints the values that were created, deleted or changed under one key
// between two snapshots. The classification is done by classifyValues; this function only
// renders it. Value names are reported in sorted order for deterministic output.
func reportValueChanges(keyPath string, before, now keyState) {
	created, deleted, changed := classifyValues(before, now)

	for _, folded := range deleted {
		b := before.values[folded]
		logger.Print(fmt.Sprintf("Value \x1b[1;91mdeleted\x1b[0m: \x1b[94m%s\x1b[0m\\%s (was %s %s)", keyPath, utils.DisplayValueName(b.name), utils.TypeName(b.value.Type), utils.FormatValue(b.value)))
	}
	for _, folded := range changed {
		b, n := before.values[folded], now.values[folded]
		logger.Print(fmt.Sprintf("Value \x1b[1;93mchanged\x1b[0m: \x1b[94m%s\x1b[0m\\%s : %s (%s) -> %s (%s)", keyPath, utils.DisplayValueName(n.name),
			utils.FormatValue(b.value), utils.TypeName(b.value.Type), utils.FormatValue(n.value), utils.TypeName(n.value.Type)))
	}
	for _, folded := range created {
		n := now.values[folded]
		logger.Print(fmt.Sprintf("Value \x1b[1;92mcreated\x1b[0m: \x1b[94m%s\x1b[0m\\%s = %s (%s)", keyPath, utils.DisplayValueName(n.name), utils.FormatValue(n.value), utils.TypeName(n.value.Type)))
	}
}

// classifyValues compares the value sets of two states of the same key and returns the folded
// value names that were created, deleted and changed, each sorted. A value is "changed" when its
// type or data differs (same semantics as the "compare" mode).
func classifyValues(before, now keyState) (created, deleted, changed []string) {
	for _, folded := range sortedValueNames(before.values) {
		b := before.values[folded]
		n, ok := now.values[folded]
		switch {
		case !ok:
			deleted = append(deleted, folded)
		case b.value.Type != n.value.Type || !bytes.Equal(b.value.Data, n.value.Data):
			changed = append(changed, folded)
		}
	}
	for _, folded := range sortedValueNames(now.values) {
		if _, ok := before.values[folded]; !ok {
			created = append(created, folded)
		}
	}
	return created, deleted, changed
}

// reportSecurityChange prints a security-descriptor change for one key when securityChanged
// reports one, showing the before and after SDDL.
func reportSecurityChange(keyPath string, before, now keyState) {
	if !securityChanged(before, now) {
		return
	}
	logger.Print(fmt.Sprintf("ACL \x1b[1;93mchanged\x1b[0m: \x1b[94m%s\x1b[0m", keyPath))
	logger.Print(fmt.Sprintf("    before: %s", before.sddl))
	logger.Print(fmt.Sprintf("    after:  %s", now.sddl))
}

// securityChanged reports whether a key's security descriptor changed between two snapshots. An
// empty SDDL on either side means that snapshot could not read the descriptor; such a transition
// is not treated as an ACL change, to avoid spurious churn from a transient read failure.
func securityChanged(before, now keyState) bool {
	return before.sddl != "" && now.sddl != "" && before.sddl != now.sddl
}

// sortedValueNames returns the keys of a value map, sorted, for deterministic iteration.
func sortedValueNames(values map[string]monitoredValue) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
