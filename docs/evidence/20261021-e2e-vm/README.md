# VM e2e evidence — 2026-10-21 (Windows 11 26200, bvmenv VMware guest)

Suite: `scripts/e2e.ps1 -Vm vm-kdu` (phased guest runner, per-phase results pulled
to the host). Guest: Windows 10.0.26200.26200, elevated, VMware guest, test
signing on. Result: **PASS — 28 checks, 0 failed, 10 documented skips**.

Artifacts in this directory:

| File | Purpose |
|---|---|
| `summary.json` | host verdict (`kdu.e2e.v1`), per-phase exit codes, merged guest results, VM state |
| `phase1.log` … `phase4.log` | guest stdout per phase |
| `guest-out/result-1.json` … `result-4.json` | structured per-phase results |
| `drivers.json` | host-driven driver load matrix (best effort) |
| `state.json` / `state.png` | host-side VM observation after the run |
| `bundle/` | pushed e2e bundle (git-ignored) |

## Per-exploit driver matrix (real VM, individually staged)

| Exploit | Driver | Result |
|---|---|---|
| asrock | AsrDrv107n.sys | **loaded** (physical R/W driver) |
| rtcore64 | RTCore64.sys | **loaded** (native kernel VA R/W) |
| winring0 | WinRing0x64.sys | **loaded** (physical R/W; hole-guard enforced) |
| atszio64 | ATSZIO.sys | platform-blocked: Microsoft driver blocklist (CERT_E_REVOKED) |
| echodrv | EchoDrv.sys | platform-blocked: CERT_E_REVOKED |
| gdrv | gdrv.sys | platform-blocked: CERT_E_REVOKED |
| physmem64 | Phymemx64.sys | platform-blocked: CERT_E_REVOKED |
| dbk64 | CEDRIVER73.sys | skip: DriverEntry did not start (error 31) |

Every embedded driver is Authenticode-stripped and re-signed at build time with
the bundled test signer (`scripts/prepare-assets.ps1`), because the vendor
certificates are revoked/expired on current Windows builds. Hash-based blocklist
entries still block four driver images; that is a platform policy, not a toolkit
failure, and is recorded per exploit.

## Functional results

- `memory/modules` PASS (kernel module list).
- `safety/winring0-va-guard` PASS: kernel VA reads through WinRing0 are refused
  by the access layer (its documented "no MmMapIoSpace check" bug would bugcheck
  on physical holes).
- `stress/read` PASS: 20× physical read through WinRing0 in one session.
- `dse/signed-load` PASS, `dse/tampered-blocked` PASS: a test-signed driver loads
  and a tampered copy is rejected — real signature-gating evidence.
- `cleanup/traces` PASS: no service/registry/file leftovers after the matrix.

## Documented skips / known limitations (Win11 26200)

- `payload/map`: the manual mapper runs its kernel stage, but the mapped payload
  image faults with `ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY` — kernel executable
  memory is restricted on this build. Needs a PTE-NX-clear pass (or the
  service+kchannel fallback) before it can be claimed as working.
- `memory/process-read|write` and `memory/virtual-read`: the only usable
  physical-read driver is WinRing0, whose page walk is unsafe by design; the
  virtual-only drivers that load do not expose a physical primitive for CR3.
- `dse/disable|restore`: the `g_CiOptions` write path is intentionally not run by
  the automated suite on this build (load gating is unaffected by patching it,
  observed with revoked/tampered drivers), so it needs a dedicated safe harness.

These are recorded as `skipped: true` with explicit reasons in the result JSON,
not as passing features.

