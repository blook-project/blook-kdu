# `--json` output schema

Every command accepts the global `--json` flag (before or after the
subcommand). Output is a single JSON document on stdout; errors are emitted as
`{"error":{"code":"<status>","message":"..."}}` and the process exits non-zero
with the documented exit code. Field names below are stable; new fields may be
added.

## `info`

```json
{
  "version": "0.1.0",
  "exploit": "gdrv",
  "driver_name": "gdrv.sys",
  "service_name": "GIO",
  "backend": "payload",
  "windows_build": 26100,
  "payload_mapped": true,
  "payload_base": "0xffffc00012340000",
  "payload_size": 52736,
  "capabilities": ["physical_read", "physical_write", "virtual_read", "..."]
}
```

## `exploits list` / `exploits probe`

```json
[
  {
    "id": "gdrv",
    "name": "GIGABYTE GDRV",
    "description": "...",
    "vendor": "GIGABYTE",
    "cve": "CVE-2018-19320",
    "driver": "gdrv.sys",
    "service": "GIO",
    "device": "\\\\.\\GIO",
    "capabilities": ["physical_read", "physical_write", "map_physical"],
    "min_build": 7600,
    "max_build": 4294967295
  }
]
```

## `modules`

```json
[
  {"name": "ntoskrnl.exe", "path": "\\SystemRoot\\system32\\ntoskrnl.exe",
   "base": "0xfffff80012340000", "size": 21295104}
]
```

## `mem phys|virt read` / `mem process read`

```json
{"address": "0xfffff80012340000", "size": 64, "hex": "4d5a900003000000..."}
```

`write` returns a short human line only. `mem virt translate`:

```json
{"virtual": "0xfffff80012340000", "physical": "0x12340000"}
```

## `mem process cr3`

```json
{"pid": 1234, "cr3": "0x1a2b3000"}
```

## `dse status`

```json
{"enabled": true, "options": "0x6", "options_address": "0xfffff8010a2b3000"}
```

## `traces` / `cleanup`

```json
{
  "clean": false,
  "findings": [
    {"category": "eventlog",
     "description": "2 Service Control Manager install event(s) reference the driver",
     "location": "System log, EventID 7045", "cleaned": false}
  ]
}
```

`cleanup --json` returns `{"clean": bool, "actions": [...], "residuals": [...]}`.

## `doctor`

```json
{"ok": false,
 "checks": [{"name": "Windows build", "result": "26100"},
            {"name": "Elevated", "result": "yes"},
            {"name": "Kernel modules visible", "result": "221"},
            {"name": "Trace scan", "result": "clean"}]}
```

## `batch`

Input file (all fields except `op` are per-op):

```json
{
  "ops": [
    {"op": "read_virtual", "address": "0xfffff80012340000", "size": 64, "out": "head.bin"},
    {"op": "translate", "address": "0xfffff80012340000"},
    {"op": "read_process", "pid": 1234, "address": "0x7ff7a0000000", "size": 16},
    {"op": "write_process", "pid": 1234, "address": "0x7ff7a0000000", "hex": "4b4455"},
    {"op": "process_cr3", "pid": 1234},
    {"op": "dse_status"},
    {"op": "dse_disable"},
    {"op": "modules"},
    {"op": "sleep", "ms": 250}
  ]
}
```

Output:

```json
{"ok": true,
 "results": [
   {"op": "read_virtual", "status": "ok", "address": "0x...", "size": 64, "hex": "..."},
   {"op": "translate", "status": "ok", "virtual": "0x...", "physical": "0x..."}
 ]}
```

`--continue-on-error` keeps going after a failed op; each failure row has
`status` (the `Status` name) and `error`. The body runs in one session, so the
driver is loaded/unloaded once and relative order matters (e.g. `dse_disable`
before writing to `ci.dll`).
