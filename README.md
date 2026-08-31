![](./.github/banner.png)

<p align="center">
      A tool to read, write, search, back up, compare, secure, and live-monitor the Windows registry (keys, values, and ACLs) on remote hosts over MS-RRP (the Remote Registry protocol, <code>\winreg</code> over DCE/RPC over SMB).
      <br>
      <a href="https://github.com/TheManticoreProject/manticore-registry/actions/workflows/release.yaml" title="Build"><img alt="Build and Release" src="https://github.com/TheManticoreProject/manticore-registry/actions/workflows/release.yaml/badge.svg"></a>
      <img alt="GitHub release (latest by date)" src="https://img.shields.io/github/v/release/TheManticoreProject/manticore-registry">
      <img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/TheManticoreProject/manticore-registry">
      <a href="https://twitter.com/intent/follow?screen_name=podalirius_" title="Follow"><img src="https://img.shields.io/twitter/follow/podalirius_?label=Podalirius&style=social"></a>
      <a href="https://www.youtube.com/c/Podalirius_?sub_confirmation=1" title="Subscribe"><img alt="YouTube Channel Subscribers" src="https://img.shields.io/youtube/channel/subscribers/UCF_x5O7CSfr82AfNVTKOv_A?style=social"></a>
      <br>
</p>

## Features

- [x] Query mode:
  - [x] Read a single value
  - [x] Enumerate the subkeys and values of a key (recursive with `-s`)
  - [x] Search a subtree for matching keys, value names, or value data (`-f`)
- [x] Find mode:
  - [x] Search a subtree for a substring (default) or a whole-string match (`--exact`)
  - [x] Match key names, value names, and/or value data (`--keys` / `--values` / `--data`)
  - [x] Filter on the value type, or search by type alone (`-t/--type`)
  - [x] Case-insensitive by default, case-sensitive with `-c`; bound the search with `--max-depth` / `--max-results`
- [x] Add mode:
  - [x] Create a key
  - [x] Set a typed value (`REG_SZ`, `REG_EXPAND_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `REG_MULTI_SZ`)
- [x] Delete mode:
  - [x] Delete a value
  - [x] Delete a key, recursively with `-r`
  - [x] Delete all values under a key (`--all-values`)
- [x] Hive maintenance:
  - [x] Save a key and its subtree to a hive file (`save`)
  - [x] Restore a hive file into an existing key (`restore`)
  - [x] Load / unload a hive file as a subkey under `HKLM` or `HKU` (`load` / `unload`)
- [x] Copy and compare:
  - [x] Recursively copy a key (values and subkeys) to another key (`copy`)
  - [x] Recursively compare two keys and report their differences (`compare`)
- [x] Import and export:
  - [x] Export a key and its subtree to a local `.reg` file in regedit format (`export`)
  - [x] Apply a local `.reg` file to the remote registry, honoring deletes (`import`)
- [x] Security descriptor mode:
  - [x] Read or set a key's owner/group/DACL/SACL as SDDL (`sd`)
- [x] Monitor mode:
  - [x] Watch a key subtree on a refresh loop and report created/deleted keys, changed values, and ACL changes as they happen (`monitor`)
- [x] Operate on the 32-bit or 64-bit registry view with `--reg32` / `--reg64`
- [x] Authentication with a password or NT/LM hashes (pass-the-hash)

## Installation

To get this tool you can either download the latest release from the [GitHub release page](https://github.com/TheManticoreProject/manticore-registry/releases) or install it with the following `go` command:

```bash
go install github.com/TheManticoreProject/manticore-registry@latest
```

## Demonstration

Every mode shares the same **SMB Connection Settings** (`--host`, `--port`, default `445`) and **Authentication** flags (`-d/--domain`, `-u/--username`, `-p/--password`, `-H/--hashes`). The registry key is given with `-k/--key` and accepts both the short (`HKLM\...`) and long (`HKEY_LOCAL_MACHINE\...`) root forms.

<details open>
<summary><b>Query Mode</b></summary>

The query mode reads a single value, enumerates a key (optionally recursively with `-s`), or searches a subtree with `-f`:

```bash
# Read a single value
./manticore-registry query --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -v ProductName

# Read the unnamed default value
./manticore-registry query --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v ''

# Enumerate the subkeys and values of a key (omit -v)
./manticore-registry query --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE'

# Recursively dump a whole subtree
./manticore-registry query --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -s

# Recursively search for a substring (use --keys / --values / --data to narrow the scope)
./manticore-registry query --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE' -f 'Acme' --keys

# Read from the 32-bit (WOW64) view
./manticore-registry query --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' --reg32 -k 'HKLM\SOFTWARE\Acme' -v Build
```

</details>


<details>
<summary><b>Find Mode</b></summary>

The find mode searches the subtree under `-k/--key`. The pattern given with `-f/--pattern` is matched as a substring by default (`--contains`), or as a whole string with `--exact`, case-insensitively unless `-c/--case-sensitive` is given. `--keys`, `--values` and `--data` select what the pattern is matched against (key names, value names, value data), and all three are searched when none is given. `-t/--type` restricts the search to values of one registry type, and can be used on its own to list every value of that type:

```bash
# Substring search over key names, value names and value data
./manticore-registry find --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE' -f 'Acme'

# Whole-string match on value names only, case-sensitive
./manticore-registry find --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE' -f 'Debug' --exact --values -c

# Search key names only
./manticore-registry find --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE' -f 'Acme' --keys

# Search value data, restricted to one value type
./manticore-registry find --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SYSTEM\CurrentControlSet\Services' -f 'powershell' --data -t REG_EXPAND_SZ

# List every value of a type, with no pattern at all
./manticore-registry find --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -t REG_MULTI_SZ

# Find the values holding empty data (an explicitly empty pattern is a real search)
./manticore-registry find --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -f '' --exact --data

# Bound a broad search: two levels deep at most, stop after 20 matches
./manticore-registry find --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE' -f 'password' --max-depth 2 --max-results 20
```

Value data is matched against every reasonable rendering of it, not just the displayed one: a `REG_DWORD` holding 16 matches `16`, `0x10`, `00000010` and `0x10 (16)`; each item of a `REG_MULTI_SZ` is matched on its own; raw bytes match both `deadbeef` and `de ad be ef`. The type filter applies to values, so it cannot be combined with `--keys`: a key name has no value type. The root key given with `-k` is itself never matched by name, only the keys found beneath it.

Every match is printed with the reason it matched:

```
[>] Searching HKLM\SOFTWARE for "Acme" (contains, case-insensitive) in key names, value names, value data
    [key]        HKLM\SOFTWARE\Acme
    [value data] HKLM\SOFTWARE\Acme\Name    REG_SZ    acme-server
    [value name] HKLM\SOFTWARE\Acme\Settings\Acme    REG_SZ    nothing to see
[>] 3 match(es).
```

A search by type alone reports each value on its type instead:

```
[>] Searching HKLM\SOFTWARE\Acme for every value of type REG_DWORD
    [value type] HKLM\SOFTWARE\Acme\Enabled    REG_DWORD    0x1 (1)
    [value type] HKLM\SOFTWARE\Acme\Settings\Port    REG_DWORD    0x1bb (443)
[>] 2 match(es).
```

The `query -f` search is kept as it was; `find` is its richer form, adding whole-string matching, case sensitivity, type filtering and the search bounds.

</details>

<details>
<summary><b>Add Mode</b></summary>

The add mode creates a key, or sets a typed value (pick exactly one value-type flag):

```bash
# Create a key (no value)
./manticore-registry add --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme'

# Set a typed value
./manticore-registry add --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v Enabled --dword 1
./manticore-registry add --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v Name    --sz 'hello'
./manticore-registry add --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v Blob    --binary deadbeef
./manticore-registry add --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v List    --multi-sz 'a,b,c'

# Empty strings and binary data are valid when the corresponding option is present
./manticore-registry add --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v Empty --sz ''
```

The mutually exclusive value-type flags are: `--sz` (`REG_SZ`), `--expand-sz` (`REG_EXPAND_SZ`), `--dword` (`REG_DWORD`, decimal or `0x`-hex), `--qword` (`REG_QWORD`, decimal or `0x`-hex), `--binary` (`REG_BINARY`, hex bytes), and `--multi-sz` (`REG_MULTI_SZ`, comma-separated).

</details>


<details>
<summary><b>Delete Mode</b></summary>

The delete mode removes a value, a key (recursively with `-r`), or all values under a key. Destructive operations prompt for confirmation unless `--force` is given:

```bash
# Delete a value
./manticore-registry delete --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v Enabled

# Delete the unnamed default value
./manticore-registry delete --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -v ''

# Delete a leaf key (prompts unless --force)
./manticore-registry delete --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' --force

# Recursively delete a key and all its subkeys
./manticore-registry delete --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' -r --force

# Delete every value under a key, keeping the key and its subkeys
./manticore-registry delete --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKCU\Software\Acme' --all-values --force
```

</details>


<details>
<summary><b>Hive Maintenance (save / restore / load / unload)</b></summary>

These operate on hive **files on the remote machine** (relative paths resolve against the Remote Registry service's working directory) and require the relevant privileges (`SeBackupPrivilege` for save, `SeRestorePrivilege` for restore/load):

```bash
# Save a key and its subtree to a hive file on the target
./manticore-registry save    --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -f 'C:\Windows\Temp\acme.hiv'

# Restore a remote hive file into an existing key (overwrites it)
./manticore-registry restore --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -f 'C:\Windows\Temp\acme.hiv'

# Load a remote hive file as a new subkey under HKLM (or HKU), then unload it
./manticore-registry load    --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\TempHive' -f 'C:\Windows\Temp\acme.hiv'
./manticore-registry unload  --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\TempHive'
```

</details>


<details>
<summary><b>Copy and Compare</b></summary>

The copy and compare modes both operate on two keys on the **same** remote machine:

```bash
# Recursively copy a key (values and subkeys) to another key
./manticore-registry copy    --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -t 'HKLM\SOFTWARE\AcmeBackup'

# Recursively compare two keys and report differences
./manticore-registry compare --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -t 'HKLM\SOFTWARE\AcmeBackup'
```

</details>


<details>
<summary><b>Export and Import (.reg files)</b></summary>

The `export` mode writes a regedit-format `.reg` file (UTF-16LE) on the **local** machine; `import` reads a **local** `.reg` file and applies it to the remote registry (it also honors the `[-key]` and `"name"=-` delete directives):

```bash
# Export a remote key subtree to a local .reg file
./manticore-registry export --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -f ./acme.reg

# Apply a local .reg file to the remote registry
./manticore-registry import --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -f ./acme.reg
```

</details>


<details>
<summary><b>Security Descriptor Mode</b></summary>

The sd mode reads a key's security descriptor as SDDL (omit `--sddl`), or sets it (pass `--sddl`). The components operated on default to owner+group+DACL for a read and DACL for a write; narrow or widen them with `--owner` / `--group` / `--dacl` / `--sacl`:

```bash
# Read the descriptor (owner+group+DACL) as SDDL, with a structured breakdown
./manticore-registry sd --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' --describe

# Set the DACL from an SDDL string
./manticore-registry sd --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' --sddl 'D:(A;;KA;;;BA)(A;;KA;;;SY)'

# Set owner, group and DACL together
./manticore-registry sd --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' --owner --group --dacl --sddl 'O:BAG:BAD:(A;;KA;;;BA)'
```

</details>


<details>
<summary><b>Monitor Mode</b></summary>

The monitor mode takes a baseline snapshot of one or more key subtrees, then re-snapshots them every `-i/--interval` seconds (default 5) and reports only the changes: keys created or deleted, values created, deleted or changed, and security-descriptor (ACL) changes. Repeat `-k/--key` to watch several subtrees at once; they are diffed together as one key set. The baseline itself is not printed; every change line is timestamped. Press Ctrl-C to stop. ACL watching covers owner+group+DACL by default; add `--sacl` to also watch the SACL (requires `SeSecurityPrivilege`):

```bash
# Watch a subtree, snapshotting every 5 seconds (default)
./manticore-registry monitor --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme'

# Watch several subtrees at once by repeating -k
./manticore-registry monitor --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -k 'HKLM\SYSTEM\CurrentControlSet\Services'

# Snapshot every 2 seconds and also watch each key's SACL
./manticore-registry monitor --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -p 'Admin123!' -k 'HKLM\SOFTWARE\Acme' -i 2 --sacl
```

</details>


<details>
<summary><b>Pass-the-hash</b></summary>

Any mode can authenticate with NT/LM hashes instead of a password using `-H/--hashes`:

```bash
./manticore-registry query --host "192.168.56.101" -d "MANTICORE.local" -u "Administrator" -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' -k 'HKLM\SOFTWARE'
```

</details>


## Usage

The first positional argument of the program is the mode:

```
./manticore-registry
manticore-registry - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: manticore-registry <add|compare|copy|delete|export|find|import|load|monitor|query|restore|save|sd|unload>

   add      Add (create) a key, or set a typed value, on a remote machine.
   compare  Recursively compare two keys on the same machine and report their differences.
   copy     Recursively copy a key (values and subkeys) to another key on the same machine.
   delete   Delete a value, or a leaf key, on a remote machine.
   export   Export a key and its subtree from the remote machine to a local .reg file.
   find     Search a key subtree for matching key names, value names, value data, or value types.
   import   Apply a local .reg file to the remote registry (create/set keys and values, honor deletes).
   load     Load a hive file on the remote machine as a new subkey under HKLM or HKU.
   monitor  Watch a key subtree on a refresh loop and report created/deleted keys, changed values, and ACL changes.
   query    Query a value, or enumerate the subkeys and values of a key, on a remote machine.
   restore  Restore a hive file on the remote machine into an existing key (overwrites it).
   save     Save a key and its subtree to a hive file on the remote machine.
   sd       Read or set the security descriptor (owner/group/DACL/SACL) of a key, as SDDL.
   unload   Unload a previously loaded hive from a subkey under HKLM or HKU.
```

Each mode then takes its own options. For example, the `query` mode:

```
./manticore-registry query
manticore-registry - by Remi GASCOU (Podalirius) @ TheManticoreProject - v1.0.0

Usage: manticore-registry query [--debug] [--domain <string>] --username <string> [--password <string>] [--hashes <string>] --key <string> [--value <string>] [--recurse] [--find <string>] [--keys] [--values] [--data] [--reg32] [--reg64] --host <string> [--port <tcp port>]

  --debug         Enable debug mode. (default: false)

  Authentication:
    -d, --domain <string>   Active Directory domain to authenticate to. (default: "")
    -u, --username <string> User to authenticate as.
    -p, --password <string> Password to authenticate with. (default: "")
    -H, --hashes <string>   NT/LM hashes, format is LMhash:NThash. (default: "")

  Configuration:
    -k, --key <string>   Registry key path (e.g. 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion').
    -v, --value <string> Value name to read. If omitted, the key's subkeys and values are enumerated. (default: "")
    -s, --recurse        Recurse into all subkeys (whole-subtree dump, or recursive search with --find). (default: false)
    -f, --find <string>  Recursively search the subtree for a case-insensitive substring. (default: "")
    --keys               With --find: match subkey names. (default: keys, values and data) (default: false)
    --values             With --find: match value names. (default: keys, values and data) (default: false)
    --data               With --find: match value data. (default: keys, values and data) (default: false)

  Registry View:
    --reg32         Operate on the 32-bit (WOW64) registry view. (default: false)
    --reg64         Operate on the 64-bit registry view. (default: false)

  SMB Connection Settings:
    --host <string>   Hostname or IP address of the target machine.
    --port <tcp port> SMB port to connect to on the target machine. (default: 445)
```

## Contributing

Pull requests are welcome. Feel free to open an issue if you want to add other features.

## Credits
  - [Remi GASCOU (Podalirius)](https://github.com/p0dalirius) for the creation of the [manticore-registry](https://github.com/TheManticoreProject/manticore-registry) project.
