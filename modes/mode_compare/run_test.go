package mode_compare

import (
	"testing"

	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
)

func TestIndexesUseCaseInsensitiveRegistryNames(t *testing.T) {
	values := indexValues([]ms_rrp.ValueEntry{{Name: "Enabled", Value: ms_rrp.DwordValue(1)}})
	if _, ok := values["enabled"]; !ok {
		t.Fatal("value index did not fold the registry value name")
	}

	subkeys := indexSubkeys([]string{"Settings"})
	if got := subkeys["settings"]; got != "Settings" {
		t.Fatalf("subkey index returned %q, want original spelling Settings", got)
	}
}
