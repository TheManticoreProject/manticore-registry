package mode_copy

import "testing"

func TestRunRejectsDestinationInsideSourceBeforeConnecting(t *testing.T) {
	err := Run("unused", 445, nil, `HKLM\Software\Acme`, `hkey_local_machine\software\acme\Backup`, 0, false)
	if err == nil {
		t.Fatal("Run accepted a copy destination inside its source")
	}
}
