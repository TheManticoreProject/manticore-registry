package utils

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/TheManticoreProject/Manticore/logger"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/dtyp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/interfaces/338cd001-2244-31f1-aaaa-900038001003/1.0/structures"
	ms_rrp "github.com/TheManticoreProject/Manticore/network/dcerpc/ms-protocols/ms-rrp"
	"github.com/TheManticoreProject/Manticore/network/dcerpc/ndr"
	smbclient "github.com/TheManticoreProject/Manticore/network/smb/client"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
	"github.com/TheManticoreProject/Manticore/windows/registry"
	"github.com/TheManticoreProject/winacl/securitydescriptor"
)

// SECURITY_INFORMATION bits ([MS-DTYP] 2.4.7): which parts of a security descriptor a
// get/set operation applies to.
const (
	SecurityInformationOwner ndr.DWORD = 0x00000001
	SecurityInformationGroup ndr.DWORD = 0x00000002
	SecurityInformationDacl  ndr.DWORD = 0x00000004
	SecurityInformationSacl  ndr.DWORD = 0x00000008
)

// AccessSystemSecurity is the ACCESS_SYSTEM_SECURITY right, required in samDesired to read
// or write the SACL.
const AccessSystemSecurity ndr.DWORD = 0x01000000

// rootLongNames maps the short root mnemonics to the long forms used in .reg file headers.
var rootLongNames = map[string]string{
	"HKLM": "HKEY_LOCAL_MACHINE",
	"HKCU": "HKEY_CURRENT_USER",
	"HKCR": "HKEY_CLASSES_ROOT",
	"HKU":  "HKEY_USERS",
	"HKCC": "HKEY_CURRENT_CONFIG",
	"HKPD": "HKEY_PERFORMANCE_DATA",
}

// ExpandRootLong rewrites a key path's leading short root mnemonic to its long form (e.g.
// "HKLM\\X" -> "HKEY_LOCAL_MACHINE\\X"), as used in .reg section headers. Paths already in
// long form are returned unchanged.
func ExpandRootLong(keyPath string) string {
	root, sub := SplitRootPath(keyPath)
	if long, ok := rootLongNames[strings.ToUpper(strings.TrimSpace(root))]; ok {
		root = long
	}
	if sub == "" {
		return root
	}
	return root + `\` + sub
}

// CanonicalKeyPath normalizes a registry path for comparisons. Registry roots are
// expanded to their long names and the result is folded to lower case because Windows
// registry key names are case-insensitive.
func CanonicalKeyPath(keyPath string) string {
	root, subkey := SplitRootPath(keyPath)
	if long, ok := rootLongNames[strings.ToUpper(strings.TrimSpace(root))]; ok {
		root = long
	}
	path := root
	if subkey != "" {
		path += `\` + strings.Trim(subkey, `\`)
	}
	return strings.ToLower(path)
}

// IsKeyDescendant reports whether candidate is strictly below parent in the registry
// hierarchy. Root aliases and character case are normalized before comparison.
func IsKeyDescendant(parent, candidate string) bool {
	p := CanonicalKeyPath(parent)
	c := CanonicalKeyPath(candidate)
	return p != "" && strings.HasPrefix(c, p+`\`)
}

// ToRegistryValue converts an ms_rrp.RegistryValue to the windows/registry.Value used by
// the regfile package (the two share the same {Type, Data} shape).
func ToRegistryValue(v ms_rrp.RegistryValue) registry.Value {
	return registry.Value{Type: v.Type, Data: v.Data}
}

// FromRegistryValue converts a windows/registry.Value to an ms_rrp.RegistryValue.
func FromRegistryValue(v registry.Value) ms_rrp.RegistryValue {
	return ms_rrp.RegistryValue{Type: v.Type, Data: v.Data}
}

// DeleteKeyTreeView deletes keyPath and its whole subtree depth-first in the selected view.
func DeleteKeyTreeView(reg *ms_rrp.RemoteRegistry, keyPath string, wow64 ndr.DWORD) error {
	if !HasSubkey(keyPath) {
		return fmt.Errorf("refusing to recursively delete root key %q", keyPath)
	}
	subkeys, err := EnumKeysView(reg, keyPath, wow64)
	if err != nil {
		return err
	}
	for _, name := range subkeys {
		if err := DeleteKeyTreeView(reg, keyPath+`\`+name, wow64); err != nil {
			return err
		}
	}
	return DeleteKeyView(reg, keyPath, wow64)
}

// ValueTypeFlags holds the mutually exclusive value-type subflags of the "add" mode.
// At most one of these is set (enforced by the goopts argument group). Each Is field records
// option presence separately so an explicitly supplied empty string remains valid data.
type ValueTypeFlags struct {
	Sz         string
	SzIs       bool
	ExpandSz   string
	ExpandSzIs bool
	Dword      string
	DwordIs    bool
	Qword      string
	QwordIs    bool
	Binary     string
	BinaryIs   bool
	MultiSz    string
	MultiSzIs  bool // true when the --multi-sz flag was supplied (so empty strings are kept)
}

// ConnectRegistry opens an authenticated SMB session to the target host, tree-connects to
// IPC$, binds the \winreg interface and returns the connected RemoteRegistry along with a
// cleanup closure that tears the whole chain down. The caller should defer the cleanup.
//
// Parameters:
//
//	host (string): The hostname or IP address of the target machine.
//	port (int): The TCP port of the SMB service (usually 445).
//	creds (*credentials.Credentials): The credentials for authentication.
//	debug (bool): A flag indicating whether to print debug information.
//
// Returns:
//
//	(*ms_rrp.RemoteRegistry): The connected remote registry client.
//	(func()): A cleanup closure releasing the registry association and the SMB session.
//	(error): An error if any step of the connection fails, nil otherwise.
func ConnectRegistry(host string, port int, creds *credentials.Credentials, debug bool) (*ms_rrp.RemoteRegistry, func(), error) {
	if debug {
		logger.Debug(fmt.Sprintf("Dialing SMB to %s:%d", host, port))
	}

	smb, err := smbclient.Dial(host, port, smbclient.Options{})
	if err != nil {
		return nil, nil, fmt.Errorf("error dialing SMB to %s:%d: %s", host, port, err)
	}

	if err := smb.Login(creds); err != nil {
		smb.Disconnect()
		return nil, nil, fmt.Errorf("error authenticating to %s: %s", host, err)
	}

	if err := smb.TreeConnect("IPC$"); err != nil {
		smb.Logoff()
		smb.Disconnect()
		return nil, nil, fmt.Errorf("error tree-connecting to IPC$ on %s: %s", host, err)
	}

	reg := ms_rrp.New(smb)
	if err := reg.Connect(); err != nil {
		smb.TreeDisconnect()
		smb.Logoff()
		smb.Disconnect()
		return nil, nil, fmt.Errorf("error binding the remote registry interface on %s: %s", host, err)
	}

	if debug {
		logger.Debug(fmt.Sprintf("Remote registry interface bound on %s", host))
	}

	cleanup := func() {
		reg.Close()
		smb.TreeDisconnect()
		smb.Logoff()
		smb.Disconnect()
	}

	return reg, cleanup, nil
}

// RegString builds a NUL-terminated counted string for a key/value/file name. [MS-RRP]
// counts the terminating NUL in the length, so it is appended explicitly, mirroring the
// ms_rrp package's own internal name builder.
func RegString(s string) dtyp.RPC_UNICODE_STRING {
	return dtyp.NewUnicodeString(s + "\x00")
}

// SplitRootPath splits "HKLM\\TempHive" into the root mnemonic ("HKLM") and the remaining
// subkey path ("TempHive"). Leading/trailing backslashes and spaces are trimmed; a path
// with no subkey returns an empty subkey.
func SplitRootPath(keyPath string) (root, subkey string) {
	p := strings.Trim(strings.TrimSpace(keyPath), `\`)
	if i := strings.IndexByte(p, '\\'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return p, ""
}

// HasSubkey reports whether keyPath names a subkey under a root (e.g. HKLM\Software) rather
// than a bare root mnemonic (e.g. HKLM). Root keys cannot be created or written to, so the
// modes that do so use this for a friendly up-front check.
func HasSubkey(keyPath string) bool {
	_, subkey := SplitRootPath(keyPath)
	return subkey != ""
}

// OpenRoot opens the predefined root key named by its mnemonic (HKLM, HKEY_LOCAL_MACHINE,
// HKCU, HKCR, HKU, HKCC, HKPD and their long forms), returning its handle. The caller owns
// the handle and must BaseRegCloseKey it.
func OpenRoot(reg *ms_rrp.RemoteRegistry, root string, samDesired ndr.DWORD) (ms_rrp.Handle, error) {
	switch strings.ToUpper(strings.TrimSpace(root)) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return reg.OpenLocalMachine(nil, samDesired)
	case "HKCU", "HKEY_CURRENT_USER":
		return reg.OpenCurrentUser(nil, samDesired)
	case "HKCR", "HKEY_CLASSES_ROOT":
		return reg.OpenClassesRoot(nil, samDesired)
	case "HKU", "HKEY_USERS":
		return reg.OpenUsers(nil, samDesired)
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return reg.OpenCurrentConfig(nil, samDesired)
	case "HKPD", "HKEY_PERFORMANCE_DATA":
		return reg.OpenPerformanceData(nil, samDesired)
	default:
		return ms_rrp.Handle{}, fmt.Errorf("unknown registry root %q", root)
	}
}

// Wow64View returns the WOW64 SAM bit to OR into samDesired for the requested registry
// view (32-bit or 64-bit), or 0 when neither view is forced.
func Wow64View(reg32, reg64 bool) ndr.DWORD {
	switch {
	case reg32:
		return ms_rrp.KeyWow6432Key
	case reg64:
		return ms_rrp.KeyWow6464Key
	default:
		return 0
	}
}

// statusContains reports whether err carries the named Win32 status mnemonic. The ms_rrp
// interface stubs embed the mnemonic in their error text; this mirrors the package's own
// (unexported) sentinel detection so loops can treat documented codes as non-fatal.
func statusContains(err error, mnemonic string) bool {
	return err != nil && strings.Contains(err.Error(), mnemonic)
}

// IsNotFound reports whether err is the status the registry returns for a key or value that
// does not exist (ERROR_FILE_NOT_FOUND). Callers making a deletion idempotent use it to treat
// an already-absent target as success.
func IsNotFound(err error) bool {
	return statusContains(err, "ERROR_FILE_NOT_FOUND")
}

// DisplayValueName renders a value name for display, showing the empty (default) value
// name as "(Default)".
func DisplayValueName(name string) string {
	if name == "" {
		return "(Default)"
	}
	return name
}

// SplitKeyParent splits "HKLM\\A\\B\\C" into the parent path "HKLM\\A\\B" and the leaf
// "C". A path with a single component (e.g. just a root) returns an empty parent.
func SplitKeyParent(keyPath string) (parent, leaf string) {
	p := strings.Trim(strings.TrimSpace(keyPath), `\`)
	if i := strings.LastIndexByte(p, '\\'); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// QueryValueHandle reads a single value under an open key, negotiating the data buffer
// size: it grows and retries on ERROR_MORE_DATA. The ms_rrp package's own value reader is
// unexported, so this reproduces it for the handle-based (WOW64-aware) code paths.
func QueryValueHandle(reg *ms_rrp.RemoteRegistry, h ms_rrp.Handle, valueName string) (ms_rrp.RegistryValue, error) {
	bufLen := uint32(256)
	for attempts := 0; attempts < 8; attempts++ {
		buf := make([]byte, bufLen)
		typ := ndr.DWORD(0)
		cb := ndr.DWORD(bufLen)
		ln := ndr.DWORD(bufLen)
		rTyp, rData, rcb, _, err := reg.BaseRegQueryValue(h, RegString(valueName), &typ, buf, &cb, &ln)
		if err != nil {
			if statusContains(err, "ERROR_MORE_DATA") && rcb != nil && uint32(*rcb) > bufLen {
				bufLen = uint32(*rcb)
				continue
			}
			return ms_rrp.RegistryValue{}, err
		}
		n := bufLen
		if rcb != nil {
			n = uint32(*rcb)
		}
		if int(n) > len(rData) {
			n = uint32(len(rData))
		}
		out := ms_rrp.RegistryValue{Data: append([]byte(nil), rData[:n]...)}
		if rTyp != nil {
			out.Type = uint32(*rTyp)
		}
		return out, nil
	}
	return ms_rrp.RegistryValue{}, fmt.Errorf("value %q kept requesting a larger buffer", valueName)
}

// QueryValueView reads a single value at keyPath in the selected registry view.
func QueryValueView(reg *ms_rrp.RemoteRegistry, keyPath, valueName string, wow64 ndr.DWORD) (ms_rrp.RegistryValue, error) {
	h, err := reg.OpenKeyByPath(keyPath, ms_rrp.KeyQueryValue|wow64)
	if err != nil {
		return ms_rrp.RegistryValue{}, err
	}
	defer reg.BaseRegCloseKey(h)
	return QueryValueHandle(reg, h, valueName)
}

// EnumKeysView lists the immediate subkeys of keyPath in the selected registry view.
func EnumKeysView(reg *ms_rrp.RemoteRegistry, keyPath string, wow64 ndr.DWORD) ([]string, error) {
	h, err := reg.OpenKeyByPath(keyPath, ms_rrp.KeyEnumerateSubKeys|wow64)
	if err != nil {
		return nil, err
	}
	defer reg.BaseRegCloseKey(h)
	return reg.EnumKeys(h)
}

// EnumValuesView lists the values of keyPath in the selected registry view.
func EnumValuesView(reg *ms_rrp.RemoteRegistry, keyPath string, wow64 ndr.DWORD) ([]ms_rrp.ValueEntry, error) {
	h, err := reg.OpenKeyByPath(keyPath, ms_rrp.KeyQueryValue|wow64)
	if err != nil {
		return nil, err
	}
	defer reg.BaseRegCloseKey(h)
	return reg.EnumValues(h)
}

// GetKeySecurity reads the security descriptor of an open key, returning its raw bytes. It
// negotiates the buffer size, growing and retrying on ERROR_INSUFFICIENT_BUFFER. secInfo
// selects which components (owner/group/DACL/SACL) to retrieve.
func GetKeySecurity(reg *ms_rrp.RemoteRegistry, h ms_rrp.Handle, secInfo ndr.DWORD) ([]byte, error) {
	size := uint32(4096)
	for attempts := 0; attempts < 6; attempts++ {
		// Per the RPC_SECURITY_DESCRIPTOR contract, a read supplies a buffer of capacity
		// CbInSecurityDescriptor with CbOutSecurityDescriptor = 0 (no valid bytes yet); the
		// server fills the returned (out) descriptor.
		in := structures.RPC_SECURITY_DESCRIPTOR{
			LpSecurityDescriptor:    make([]uint8, size),
			CbInSecurityDescriptor:  ndr.DWORD(size),
			CbOutSecurityDescriptor: 0,
		}
		out, err := reg.BaseRegGetKeySecurity(h, secInfo, in)
		if err != nil {
			if statusContains(err, "ERROR_INSUFFICIENT_BUFFER") && uint32(out.CbOutSecurityDescriptor) > size {
				size = uint32(out.CbOutSecurityDescriptor)
				continue
			}
			return nil, err
		}
		data := out.LpSecurityDescriptor
		n := uint32(out.CbOutSecurityDescriptor)
		if int(n) > len(data) {
			// The server reported more bytes than it returned; grow and retry rather than
			// hand back an under-filled (or over-long) buffer.
			if n > size {
				size = n
				continue
			}
			n = uint32(len(data))
		}
		return append([]byte(nil), data[:n]...), nil
	}
	return nil, fmt.Errorf("the security descriptor kept requesting a larger buffer")
}

// ReadKeySDDLView reads the security descriptor of keyPath in the selected registry view and
// renders it as an SDDL string. secInfo selects which components (owner/group/DACL/SACL) to
// retrieve; when the SACL bit is set, ACCESS_SYSTEM_SECURITY is added to the access request
// (the caller still needs SeSecurityPrivilege for that to succeed). It is shared by the "sd"
// and "monitor" modes so the read + SDDL conversion stay identical.
func ReadKeySDDLView(reg *ms_rrp.RemoteRegistry, keyPath string, secInfo ndr.DWORD, wow64 ndr.DWORD) (string, error) {
	samDesired := ms_rrp.MaximumAllowed | wow64
	if secInfo&SecurityInformationSacl != 0 {
		samDesired |= AccessSystemSecurity
	}

	h, err := reg.OpenKeyByPath(keyPath, samDesired)
	if err != nil {
		return "", err
	}
	defer reg.BaseRegCloseKey(h)

	raw, err := GetKeySecurity(reg, h, secInfo)
	if err != nil {
		return "", err
	}

	var ntsd securitydescriptor.NtSecurityDescriptor
	if _, err := ntsd.Unmarshal(raw); err != nil {
		return "", err
	}
	return ntsd.ToSDDLString()
}

// SetKeySecurity writes the raw security-descriptor bytes onto an open key. secInfo selects
// which components are applied.
func SetKeySecurity(reg *ms_rrp.RemoteRegistry, h ms_rrp.Handle, secInfo ndr.DWORD, sd []byte) error {
	desc := structures.RPC_SECURITY_DESCRIPTOR{
		LpSecurityDescriptor:    append([]uint8(nil), sd...),
		CbInSecurityDescriptor:  ndr.DWORD(len(sd)),
		CbOutSecurityDescriptor: ndr.DWORD(len(sd)),
	}
	return reg.BaseRegSetKeySecurity(h, secInfo, desc)
}

// SetValueView writes a value at keyPath in the selected registry view. The key must
// already exist.
func SetValueView(reg *ms_rrp.RemoteRegistry, keyPath, valueName string, value ms_rrp.RegistryValue, wow64 ndr.DWORD) error {
	h, err := reg.OpenKeyByPath(keyPath, ms_rrp.KeySetValue|wow64)
	if err != nil {
		return err
	}
	defer reg.BaseRegCloseKey(h)
	data := value.Data
	if data == nil {
		data = make([]byte, 0)
	}
	return reg.BaseRegSetValue(h, RegString(valueName), ndr.DWORD(value.Type), data, ndr.DWORD(len(data)))
}

// DeleteValueView removes a value at keyPath in the selected registry view.
func DeleteValueView(reg *ms_rrp.RemoteRegistry, keyPath, valueName string, wow64 ndr.DWORD) error {
	h, err := reg.OpenKeyByPath(keyPath, ms_rrp.KeySetValue|wow64)
	if err != nil {
		return err
	}
	defer reg.BaseRegCloseKey(h)
	return reg.BaseRegDeleteValue(h, RegString(valueName))
}

// DeleteKeyView deletes the leaf key at keyPath in the selected registry view. The key
// must have no subkeys. When no view is forced it defers to the library's DeleteKeyByPath;
// otherwise it opens the parent in the requested view and deletes the leaf by name.
func DeleteKeyView(reg *ms_rrp.RemoteRegistry, keyPath string, wow64 ndr.DWORD) error {
	if wow64 == 0 {
		return reg.DeleteKeyByPath(keyPath)
	}
	parent, leaf := SplitKeyParent(keyPath)
	if leaf == "" {
		return fmt.Errorf("refusing to delete root key %q", keyPath)
	}
	ph, err := reg.OpenKeyByPath(parent, ms_rrp.MaximumAllowed|wow64)
	if err != nil {
		return err
	}
	defer reg.BaseRegCloseKey(ph)
	return reg.BaseRegDeleteKey(ph, RegString(leaf))
}

// BuildRegistryValue builds an ms_rrp.RegistryValue from the mutually exclusive value-type
// subflags of the "add" mode. The first subflag that was supplied wins.
//
// Returns:
//
//	(ms_rrp.RegistryValue): The constructed value (zero value when none was provided).
//	(bool): True if a value-type subflag was provided, false otherwise.
//	(error): An error if the provided data could not be parsed, nil otherwise.
func BuildRegistryValue(flags ValueTypeFlags) (ms_rrp.RegistryValue, bool, error) {
	switch {
	case flags.SzIs || flags.Sz != "":
		return ms_rrp.StringValue(flags.Sz), true, nil

	case flags.ExpandSzIs || flags.ExpandSz != "":
		return ms_rrp.ExpandStringValue(flags.ExpandSz), true, nil

	case flags.DwordIs || flags.Dword != "":
		n, err := strconv.ParseUint(flags.Dword, 0, 32)
		if err != nil {
			return ms_rrp.RegistryValue{}, false, fmt.Errorf("invalid REG_DWORD value %q: %s", flags.Dword, err)
		}
		return ms_rrp.DwordValue(uint32(n)), true, nil

	case flags.QwordIs || flags.Qword != "":
		n, err := strconv.ParseUint(flags.Qword, 0, 64)
		if err != nil {
			return ms_rrp.RegistryValue{}, false, fmt.Errorf("invalid REG_QWORD value %q: %s", flags.Qword, err)
		}
		return ms_rrp.QwordValue(n), true, nil

	case flags.BinaryIs || flags.Binary != "":
		raw, err := hex.DecodeString(strings.ReplaceAll(flags.Binary, " ", ""))
		if err != nil {
			return ms_rrp.RegistryValue{}, false, fmt.Errorf("invalid REG_BINARY value %q (expected hex): %s", flags.Binary, err)
		}
		value := ms_rrp.BinaryValue(raw)
		if value.Data == nil {
			value.Data = make([]byte, 0)
		}
		return value, true, nil

	case flags.MultiSzIs:
		items := []string{}
		if flags.MultiSz != "" {
			items = strings.Split(flags.MultiSz, ",")
		}
		return ms_rrp.MultiStringValue(items), true, nil
	}

	return ms_rrp.RegistryValue{}, false, nil
}

// TypeName returns the REG_* mnemonic for a registry value type.
func TypeName(t uint32) string {
	switch t {
	case ms_rrp.RegNone:
		return "REG_NONE"
	case ms_rrp.RegSz:
		return "REG_SZ"
	case ms_rrp.RegExpandSz:
		return "REG_EXPAND_SZ"
	case ms_rrp.RegBinary:
		return "REG_BINARY"
	case ms_rrp.RegDword:
		return "REG_DWORD"
	case ms_rrp.RegLink:
		return "REG_LINK"
	case ms_rrp.RegMultiSz:
		return "REG_MULTI_SZ"
	case ms_rrp.RegQword:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("0x%x", t)
	}
}

// valueTypeNames maps the REG_* mnemonics to their value-type constants, for parsing the
// type filter of the "find" mode.
var valueTypeNames = map[string]uint32{
	"REG_NONE":      ms_rrp.RegNone,
	"REG_SZ":        ms_rrp.RegSz,
	"REG_EXPAND_SZ": ms_rrp.RegExpandSz,
	"REG_BINARY":    ms_rrp.RegBinary,
	"REG_DWORD":     ms_rrp.RegDword,
	"REG_LINK":      ms_rrp.RegLink,
	"REG_MULTI_SZ":  ms_rrp.RegMultiSz,
	"REG_QWORD":     ms_rrp.RegQword,
}

// ParseValueType resolves a user-supplied registry value type to its numeric constant. Both
// the full mnemonic and its short form are accepted, case-insensitively and with dashes or
// underscores ("REG_MULTI_SZ", "multi-sz"), as is a decimal or 0x-hex type number for the
// types that have no mnemonic.
//
// Parameters:
//
//	s (string): The value type to parse.
//
// Returns:
//
//	(uint32): The registry value type.
//	(error): An error if s names no known type and is not a valid type number, nil otherwise.
func ParseValueType(s string) (uint32, error) {
	name := strings.ToUpper(strings.TrimSpace(s))
	name = strings.ReplaceAll(name, "-", "_")
	if !strings.HasPrefix(name, "REG_") {
		name = "REG_" + name
	}
	if t, ok := valueTypeNames[name]; ok {
		return t, nil
	}
	if n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32); err == nil {
		return uint32(n), nil
	}
	return 0, fmt.Errorf("unknown registry value type %q (expected REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_LINK, REG_MULTI_SZ, REG_QWORD, or a numeric type)", s)
}

// FormatValue renders a registry value as a human-readable string, decoded according to its
// type, for display in the "query" mode.
func FormatValue(v ms_rrp.RegistryValue) string {
	switch v.Type {
	case ms_rrp.RegSz, ms_rrp.RegExpandSz, ms_rrp.RegLink:
		return v.String()

	case ms_rrp.RegDword:
		if n, ok := v.Uint32(); ok {
			return fmt.Sprintf("0x%x (%d)", n, n)
		}
		return hex.EncodeToString(v.Data)

	case ms_rrp.RegQword:
		if n, ok := v.Uint64(); ok {
			return fmt.Sprintf("0x%x (%d)", n, n)
		}
		return hex.EncodeToString(v.Data)

	case ms_rrp.RegMultiSz:
		return strings.Join(v.MultiString(), ", ")

	default:
		return hex.EncodeToString(v.Data)
	}
}

// ValueDataCandidates renders the data of a registry value as every string a user could
// reasonably search for, so that searching value data is not tied to one presentation. The
// display form produced by FormatValue always comes first, followed by the type-specific
// alternatives: the plain decimal and hex forms of a number, each item of a REG_MULTI_SZ on
// its own, and the space-separated hex form of raw bytes.
//
// Parameters:
//
//	v (ms_rrp.RegistryValue): The value whose data to render.
//
// Returns:
//
//	([]string): The candidate renderings of the value data, never empty.
func ValueDataCandidates(v ms_rrp.RegistryValue) []string {
	candidates := []string{FormatValue(v)}

	switch v.Type {
	case ms_rrp.RegDword:
		if n, ok := v.Uint32(); ok {
			candidates = append(candidates, strconv.FormatUint(uint64(n), 10), fmt.Sprintf("0x%x", n), fmt.Sprintf("%08x", n))
		}

	case ms_rrp.RegQword:
		if n, ok := v.Uint64(); ok {
			candidates = append(candidates, strconv.FormatUint(n, 10), fmt.Sprintf("0x%x", n), fmt.Sprintf("%016x", n))
		}

	case ms_rrp.RegMultiSz:
		candidates = append(candidates, v.MultiString()...)

	case ms_rrp.RegSz, ms_rrp.RegExpandSz, ms_rrp.RegLink:
		// FormatValue already yields the decoded string; there is no other sensible form.

	default:
		candidates = append(candidates, spacedHex(v.Data))
	}

	return candidates
}

// spacedHex renders raw bytes as lower-case hex pairs separated by spaces ("de ad be ef"),
// the form regedit displays binary data in.
func spacedHex(data []byte) string {
	pairs := make([]string, 0, len(data))
	for _, b := range data {
		pairs = append(pairs, fmt.Sprintf("%02x", b))
	}
	return strings.Join(pairs, " ")
}
