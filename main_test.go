package main

import (
	"os"
	"testing"
)

func resetCLIState() {
	mode = ""
	debug = false
	keyPath = ""
	valueName = ""
	valueNameProvided = false
	valSz, valExpandSz, valDword, valQword, valBinary, valMultiSz = "", "", "", "", "", ""
	valSzProvided, valExpandSzProvided = false, false
	valDwordProvided, valQwordProvided = false, false
	valBinaryProvided, valMultiSzProvided = false, false
	host, authUsername = "", ""
	findPattern, findType = "", ""
	findPatternProvided = false
	findExact, findContains, findCaseSensitive = false, false, false
	findKeys, findValues, findData = false, false, false
	findMaxDepth, findMaxResults = 0, 0
}

func parseTestArgs(t *testing.T, args ...string) {
	t.Helper()
	oldArgs := os.Args
	t.Cleanup(func() { os.Args = oldArgs })
	resetCLIState()
	os.Args = append([]string{"manticore-registry"}, args...)
	parseArgs()
}

func TestParseArgsTracksEmptyDefaultValueName(t *testing.T) {
	for _, command := range []string{"query", "delete"} {
		t.Run(command, func(t *testing.T) {
			parseTestArgs(t, command, "--host", "example", "-u", "user", "-k", `HKLM\Software\Acme`, "--value", "")
			if !valueNameProvided || valueName != "" {
				t.Fatalf("empty --value presence was lost: provided=%v value=%q", valueNameProvided, valueName)
			}
		})
	}
}

func TestParseArgsTracksEmptyTypedValues(t *testing.T) {
	tests := []struct {
		flag    string
		present func() bool
	}{
		{"--sz", func() bool { return valSzProvided }},
		{"--expand-sz", func() bool { return valExpandSzProvided }},
		{"--binary", func() bool { return valBinaryProvided }},
		{"--multi-sz", func() bool { return valMultiSzProvided }},
	}
	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			parseTestArgs(t, "add", "--host", "example", "-u", "user", "-k", `HKLM\Software\Acme`, tt.flag, "")
			if !tt.present() {
				t.Fatalf("presence of %s with empty data was lost", tt.flag)
			}
		})
	}
}

func TestParseArgsTracksEmptyFindPattern(t *testing.T) {
	parseTestArgs(t, "find", "--host", "example", "-u", "user", "-k", `HKLM\Software\Acme`, "--pattern", "", "--exact")
	if !findPatternProvided || findPattern != "" {
		t.Fatalf("empty --pattern presence was lost: provided=%v pattern=%q", findPatternProvided, findPattern)
	}
}

func TestParseArgsReadsFindCriteria(t *testing.T) {
	parseTestArgs(t, "find", "--host", "example", "-u", "user", "-k", `HKLM\SOFTWARE`, "-f", "Acme", "-t", "REG_SZ", "-c", "--values", "--max-depth", "3", "--max-results", "10")
	switch {
	case findPattern != "Acme":
		t.Fatalf("--pattern = %q, want Acme", findPattern)
	case findType != "REG_SZ":
		t.Fatalf("--type = %q, want REG_SZ", findType)
	case !findCaseSensitive:
		t.Fatal("--case-sensitive was not parsed")
	case !findValues || findKeys || findData:
		t.Fatalf("scope was keys=%v values=%v data=%v, want value names only", findKeys, findValues, findData)
	case findMaxDepth != 3 || findMaxResults != 10:
		t.Fatalf("limits were max-depth=%d max-results=%d, want 3/10", findMaxDepth, findMaxResults)
	}
}
