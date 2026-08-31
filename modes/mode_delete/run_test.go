package mode_delete

import "testing"

func TestDeleteKeyRejectsBareRootBeforeConnecting(t *testing.T) {
	for _, root := range []string{"HKLM", "HKEY_LOCAL_MACHINE", `\HKCU\`} {
		if err := DeleteKey("unused", 445, nil, root, true, true, 0, false); err == nil {
			t.Fatalf("DeleteKey(%q) accepted a bare registry root", root)
		}
	}
}
