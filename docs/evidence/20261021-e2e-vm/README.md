# VM e2e evidence — 2026-10-21 (Windows 11 26200, bvmenv VMware guest)

Suite: `scripts/e2e.ps1 -Vm vm-kdu` (phased guest runner; per-phase results are
pulled to the host after every phase). Guest: Windows 10.0.26200.26200,
elevated, VMware guest. Toolkit: blook-kdu **1.0.2**. Harness: **bvmenv 0.1.12**
(`bvmenv-6e83eb6.exe`, sha256
`36ae48a8f8949fba0fb81a6dd8584e43a9b43ceade20d094f5fb6587f3745c35`), recorded in
`summary.json` as `version`, `bvmenv_version`, `bvmenv_sha256`.

Result: **PASS — 39 checks, 0 failed, 16 documented skips**, all four phase exit
codes 0.

## Payload backend (blook-drv-lite, service path)

| Case | Result |
|---|---|
| `payload/map` | PASS — service-loaded drv-lite at a kernel base |
| `payload/service-running` | PASS — `kduPayload` STATE 4 RUNNING during the client test |
| `memory/process-read` | PASS — CR3 read of the client process matched the pattern |
| `memory/process-write` | PASS — CR3 write + read-back matched |
| `dse/signed-load` | PASS — SPC-signed driver loads |
| `dse/tampered-blocked` | PASS — tampered copy rejected |

The payload client also exercises kernel VA read, physical read, module list and
handle rewriting (`kdu payload load --json`); the same self-test runs in CI's
`kernel-load-smoke` job.

## Per-exploit driver matrix (individually staged)

16 exploits are compiled in. Only drivers that are safe to start on a current
VM are started; the rest are recorded as not-started:

- started: `asrock`, `rtcore64`, `winring0`
- not started (blocklisted/revoked or unsafe raw image): `atszio64`, `dbk64`,
  `directio64`, `echodrv`, `gdrv`, `gmer`, `kph`, `lha`, `mimidrv`, `msio64`,
  `physmem64`, `tpw`, `amd`
- `dbk64` also reports DriverEntry failure on this build

Vendor drivers are embedded **as shipped** — no Authenticode stripping and no
re-signing. Microsoft's blocklist/revocation policy is recorded per exploit.

## Documented skips / known limitations (Win11 26200)

- `dse/disable`, `dse/unsigned-load`, `dse/restore`: drv-lite reports its
  `g_CiOptions` patch unsupported on this build (26200); status is still
  readable through the driver backend. VM-only.
- manual-map payload: mapped images cannot execute on 26200
  (`ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY`); the service path is used instead.
  The manual mapper remains available for builds with executable kernel memory
  (PTE-NX fix tracked for a later release).
- WinRing0 VA-hole guard, signed-driver gating, trace scan and repeated loads
  are exercised and pass.
