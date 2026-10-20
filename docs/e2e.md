# End-to-end testing in a VM

Host unit tests cover the pure logic (page tables, IOCTL encoding, PE parsing,
trace bookkeeping) but they cannot prove that loading a real vulnerable driver,
mapping the payload and touching kernel memory works. That is what the VM e2e
suite is for.

## Infrastructure

`env` owns the VMware infrastructure and the `bvmenv` CLI
(`blook-project/blook-vmware-environment`). kdu never calls `vmrun` directly:

```powershell
bvmenv create vm-kdu            # linked clone of the clean Win11 base snapshot
bvmenv push vm-kdu artifacts/e2e-bundle -Dest C:\e2e
bvmenv exec vm-kdu "C:\e2e\run.ps1" --elevated --timeout 600 --artifacts out/
bvmenv state vm-kdu --json      # host-side state: running/bsod/hang + screenshot
bvmenv reset vm-kdu
```

The base image has test signing enabled and Secure Boot off, so the bundled
signed drivers install normally and the manual mapper does not need a
production signature.

## Suite (per run)

Every step records a result row; the runner writes `result.json`, keeps the
state screenshots and log heads, and resets the VM at the end.

| Step | What it proves |
|---|---|
| `exploits` lifecycle | for every exploit: install driver as a service, open device, read a known kernel page, unload, verify service/file/registry removed |
| payload mapping | map `kdu_payload.sys` through each physical-write exploit, kchannel attach, `kdu info` shows backend=payload |
| memory round-trips | physical read/write, kernel virtual read/write, process read/write (write a marker into a helper process, read it back through CR3) |
| DSE | `dse status`, `dse disable`, load an unsigned test driver (`tests/guest`), `dse restore`, driver load fails again |
| module enumeration / dump | `modules` contains ntoskrnl; `dump-driver ntoskrnl.exe` produces an MZ image with a valid PE header |
| stress | 50x map/unmap and 200x read/write round-trips without leaks or hangs |
| cleanup | `cleanup --event-log`, `doctor --traces` returns clean except documented residuals |
| crash detection | after each step `bvmenv state` must report `running`; a BSOD/hang fails the step and is preserved as evidence |

## Running it

```powershell
# from the repo root, with bvmenv on PATH and the base VM provisioned
pwsh scripts/e2e.ps1 -Vm vm-kdu -Out docs/evidence/$(Get-Date -Format yyyyMMdd)-e2e
```

The runner is intentionally thin: it builds a bundle, pushes it, invokes the
in-guest PowerShell runner as an elevated command and copies the artifacts back.
Results are committed under `docs/evidence/<date>-<slug>/` (JSON + key
screenshots + log summaries; large logs are stored as hashes/head+tail).
