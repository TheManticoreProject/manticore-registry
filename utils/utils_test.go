package utils

import (
	"testing"

	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
)

func TestBuildRegistryValue(t *testing.T) {
	tests := []struct {
		name      string
		flags     ValueTypeFlags
		wantProv  bool
		wantType  uint32
		wantErr   bool
		wantValue string // FormatValue output, when relevant
	}{
		{name: "none", flags: ValueTypeFlags{}, wantProv: false},
		{name: "sz", flags: ValueTypeFlags{Sz: "hello"}, wantProv: true, wantType: ms_rrp.RegSz, wantValue: "hello"},
		{name: "empty-sz", flags: ValueTypeFlags{SzIs: true}, wantProv: true, wantType: ms_rrp.RegSz, wantValue: ""},
		{name: "expand-sz", flags: ValueTypeFlags{ExpandSz: "%PATH%"}, wantProv: true, wantType: ms_rrp.RegExpandSz, wantValue: "%PATH%"},
		{name: "empty-expand-sz", flags: ValueTypeFlags{ExpandSzIs: true}, wantProv: true, wantType: ms_rrp.RegExpandSz, wantValue: ""},
		{name: "dword-dec", flags: ValueTypeFlags{Dword: "16"}, wantProv: true, wantType: ms_rrp.RegDword, wantValue: "0x10 (16)"},
		{name: "dword-hex", flags: ValueTypeFlags{Dword: "0x10"}, wantProv: true, wantType: ms_rrp.RegDword, wantValue: "0x10 (16)"},
		{name: "dword-bad", flags: ValueTypeFlags{Dword: "notanumber"}, wantErr: true},
		{name: "empty-dword", flags: ValueTypeFlags{DwordIs: true}, wantErr: true},
		{name: "qword-hex", flags: ValueTypeFlags{Qword: "0xff"}, wantProv: true, wantType: ms_rrp.RegQword, wantValue: "0xff (255)"},
		{name: "binary", flags: ValueTypeFlags{Binary: "deadbeef"}, wantProv: true, wantType: ms_rrp.RegBinary, wantValue: "deadbeef"},
		{name: "empty-binary", flags: ValueTypeFlags{BinaryIs: true}, wantProv: true, wantType: ms_rrp.RegBinary, wantValue: ""},
		{name: "binary-spaced", flags: ValueTypeFlags{Binary: "de ad be ef"}, wantProv: true, wantType: ms_rrp.RegBinary, wantValue: "deadbeef"},
		{name: "binary-bad", flags: ValueTypeFlags{Binary: "zz"}, wantErr: true},
		{name: "multi-sz", flags: ValueTypeFlags{MultiSz: "a,b,c", MultiSzIs: true}, wantProv: true, wantType: ms_rrp.RegMultiSz, wantValue: "a, b, c"},
		{name: "empty-multi-sz", flags: ValueTypeFlags{MultiSzIs: true}, wantProv: true, wantType: ms_rrp.RegMultiSz, wantValue: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, provided, err := BuildRegistryValue(tt.flags)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if provided != tt.wantProv {
				t.Fatalf("provided = %v, want %v", provided, tt.wantProv)
			}
			if !provided {
				return
			}
			if value.Type != tt.wantType {
				t.Errorf("type = %d, want %d", value.Type, tt.wantType)
			}
			if tt.name == "empty-binary" && value.Data == nil {
				t.Error("empty REG_BINARY data is nil; NDR requires a non-nil [ref] pointer")
			}
			if got := FormatValue(value); got != tt.wantValue {
				t.Errorf("FormatValue = %q, want %q", got, tt.wantValue)
			}
		})
	}
}

func TestIsKeyDescendant(t *testing.T) {
	tests := []struct {
		name, parent, candidate string
		want                    bool
	}{
		{"direct child", `HKLM\Software\Acme`, `HKLM\Software\Acme\Backup`, true},
		{"aliases and case", `hklm\SOFTWARE\Acme`, `HKEY_LOCAL_MACHINE\software\acme\backup`, true},
		{"same key", `HKLM\Software\Acme`, `HKLM\Software\Acme`, false},
		{"similar prefix", `HKLM\Software\Acme`, `HKLM\Software\AcmeBackup`, false},
		{"different root", `HKLM\Software`, `HKCU\Software\Backup`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsKeyDescendant(tt.parent, tt.candidate); got != tt.want {
				t.Fatalf("IsKeyDescendant(%q, %q) = %v, want %v", tt.parent, tt.candidate, got, tt.want)
			}
		})
	}
}

func TestDeleteKeyTreeViewRejectsBareRootBeforeEnumeration(t *testing.T) {
	if err := DeleteKeyTreeView(nil, "HKEY_LOCAL_MACHINE", 0); err == nil {
		t.Fatal("DeleteKeyTreeView accepted a bare registry root")
	}
}

func TestParseValueType(t *testing.T) {
	tests := []struct {
		input   string
		want    uint32
		wantErr bool
	}{
		{input: "REG_SZ", want: ms_rrp.RegSz},
		{input: "reg_sz", want: ms_rrp.RegSz},
		{input: "sz", want: ms_rrp.RegSz},
		{input: " REG_EXPAND_SZ ", want: ms_rrp.RegExpandSz},
		{input: "expand-sz", want: ms_rrp.RegExpandSz},
		{input: "multi_sz", want: ms_rrp.RegMultiSz},
		{input: "binary", want: ms_rrp.RegBinary},
		{input: "dword", want: ms_rrp.RegDword},
		{input: "qword", want: ms_rrp.RegQword},
		{input: "link", want: ms_rrp.RegLink},
		{input: "none", want: ms_rrp.RegNone},
		{input: "11", want: 11},
		{input: "0xb", want: 11},
		{input: "REG_NOPE", wantErr: true},
		{input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseValueType(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseValueType(%q) returned %#x, want an error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseValueType(%q) errored: %s", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("ParseValueType(%q) = %#x, want %#x", tt.input, got, tt.want)
			}
		})
	}
}

func TestValueDataCandidates(t *testing.T) {
	tests := []struct {
		name  string
		value ms_rrp.RegistryValue
		want  []string // every rendering that must be searchable
	}{
		{name: "sz", value: ms_rrp.StringValue("Acme"), want: []string{"Acme"}},
		{name: "dword", value: ms_rrp.DwordValue(16), want: []string{"0x10 (16)", "16", "0x10", "00000010"}},
		{name: "qword", value: ms_rrp.QwordValue(255), want: []string{"0xff (255)", "255", "0xff", "00000000000000ff"}},
		{name: "multi-sz", value: ms_rrp.MultiStringValue([]string{"a", "b"}), want: []string{"a, b", "a", "b"}},
		{name: "binary", value: ms_rrp.BinaryValue([]byte{0xde, 0xad, 0xbe, 0xef}), want: []string{"deadbeef", "de ad be ef"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValueDataCandidates(tt.value)
			if len(got) == 0 || got[0] != FormatValue(tt.value) {
				t.Fatalf("candidates %q do not start with the displayed form %q", got, FormatValue(tt.value))
			}
			for _, want := range tt.want {
				found := false
				for _, candidate := range got {
					if candidate == want {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("candidates %q are missing the rendering %q", got, want)
				}
			}
		})
	}
}
