package mode_monitor

import (
	"strings"
	"testing"

	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
)

// keyWith builds a keyState from a SDDL string and a set of values named as the server would
// spell them, indexing them the way takeSnapshot does: by folded name, keeping the spelling.
func keyWith(sddl string, values map[string]ms_rrp.RegistryValue) keyState {
	indexed := make(map[string]monitoredValue, len(values))
	for name, value := range values {
		indexed[strings.ToLower(name)] = monitoredValue{name: name, value: value}
	}
	return keyState{values: indexed, sddl: sddl}
}

func TestDiffKeys(t *testing.T) {
	before := snapshot{
		`HKLM\SOFTWARE\Acme`:       keyWith("D:(A;;KA;;;BA)", nil),
		`HKLM\SOFTWARE\Acme\Stale`: keyWith("D:(A;;KA;;;BA)", nil),
	}
	now := snapshot{
		`HKLM\SOFTWARE\Acme`:     keyWith("D:(A;;KA;;;BA)", nil),
		`HKLM\SOFTWARE\Acme\New`: keyWith("D:(A;;KA;;;BA)", nil),
	}

	deleted, created := diffKeys(before, now)

	if len(deleted) != 1 || deleted[0] != `HKLM\SOFTWARE\Acme\Stale` {
		t.Fatalf("deleted = %v, want only the Stale subkey", deleted)
	}
	if len(created) != 1 || created[0] != `HKLM\SOFTWARE\Acme\New` {
		t.Fatalf("created = %v, want only the New subkey", created)
	}
}

func TestDiffKeysNoChange(t *testing.T) {
	snap := snapshot{`HKLM\SOFTWARE\Acme`: keyWith("D:(A;;KA;;;BA)", nil)}

	deleted, created := diffKeys(snap, snap)
	if len(deleted) != 0 || len(created) != 0 {
		t.Fatalf("steady state should report no key changes, got deleted=%d created=%d", len(deleted), len(created))
	}
}

func TestSortedCommonKeys(t *testing.T) {
	before := snapshot{
		`HKLM\B`: keyWith("", nil),
		`HKLM\A`: keyWith("", nil),
		`HKLM\C`: keyWith("", nil), // only in before
	}
	now := snapshot{
		`HKLM\A`: keyWith("", nil),
		`HKLM\B`: keyWith("", nil),
		`HKLM\D`: keyWith("", nil), // only in now
	}

	common := sortedCommonKeys(before, now)
	if len(common) != 2 || common[0] != `HKLM\A` || common[1] != `HKLM\B` {
		t.Fatalf("common = %v, want sorted [HKLM\\A HKLM\\B]", common)
	}
}

// valueChange classifies how reportValueChanges sees one value name between two states, without
// depending on the printed text: created, deleted, changed or unchanged.
func TestValueDiffSemantics(t *testing.T) {
	sz := func(s string) ms_rrp.RegistryValue { return ms_rrp.StringValue(s) }

	before := keyWith("D:(A;;KA;;;BA)", map[string]ms_rrp.RegistryValue{
		"Keep":   sz("same"),
		"Change": sz("old"),
		"Drop":   sz("gone"),
	})
	now := keyWith("D:(A;;KA;;;BA)", map[string]ms_rrp.RegistryValue{
		"Keep":   sz("same"),
		"Change": sz("new"),
		"Add":    sz("fresh"),
	})

	created, deleted, changed := classifyValues(before, now)

	if len(created) != 1 || created[0] != "add" {
		t.Fatalf("created = %v, want [add]", created)
	}
	if len(deleted) != 1 || deleted[0] != "drop" {
		t.Fatalf("deleted = %v, want [drop]", deleted)
	}
	if len(changed) != 1 || changed[0] != "change" {
		t.Fatalf("changed = %v, want [change]", changed)
	}
}

// A registry value name is case-insensitive, so the same value spelled differently between two
// snapshots is the same value: unchanged, not a delete plus a create.
func TestValueDiffFoldsNameCase(t *testing.T) {
	before := keyWith("D:(A;;KA;;;BA)", map[string]ms_rrp.RegistryValue{"Enabled": ms_rrp.DwordValue(1)})
	now := keyWith("D:(A;;KA;;;BA)", map[string]ms_rrp.RegistryValue{"enabled": ms_rrp.DwordValue(1)})

	created, deleted, changed := classifyValues(before, now)
	if len(created) != 0 || len(deleted) != 0 || len(changed) != 0 {
		t.Fatalf("a case-only rename reported created=%v deleted=%v changed=%v, want no change", created, deleted, changed)
	}

	// The data still counts: same name, new data, is one change.
	now = keyWith("D:(A;;KA;;;BA)", map[string]ms_rrp.RegistryValue{"enabled": ms_rrp.DwordValue(0)})
	created, deleted, changed = classifyValues(before, now)
	if len(created) != 0 || len(deleted) != 0 || len(changed) != 1 {
		t.Fatalf("a data change under a case-only rename reported created=%v deleted=%v changed=%v, want one change", created, deleted, changed)
	}
}

func TestSecurityChanged(t *testing.T) {
	tests := []struct {
		name           string
		before, after  string
		wantSecChanged bool
	}{
		{"identical", "D:(A;;KA;;;BA)", "D:(A;;KA;;;BA)", false},
		{"differs", "D:(A;;KA;;;BA)", "D:(A;;KA;;;WD)", true},
		{"unreadable before", "", "D:(A;;KA;;;BA)", false},
		{"unreadable after", "D:(A;;KA;;;BA)", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := securityChanged(keyWith(tc.before, nil), keyWith(tc.after, nil))
			if got != tc.wantSecChanged {
				t.Fatalf("securityChanged(%q, %q) = %v, want %v", tc.before, tc.after, got, tc.wantSecChanged)
			}
		})
	}
}
