# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: True   unsafe-physical: True
- kdu.exe sha256: 34cecd98c67b934acd1e7110bcb2dccbbd582638ac333fd9793ccbf5c4a74a99   timeout/id: 90s   generated: 2026-10-22T10:20:27.2201016+08:00

**4 exploit(s): 0 PASS, 1 FAIL, 3 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| lha | CRASH | bugcheck |  |  | bvmenv: error: guest script failed (timeout): |
| phydmacc | FAIL | primitive-failed |  |  | FAIL phydmacc cannot read ntoskrnl image header |
| winiodrv_b | CRASH | bugcheck |  |  | bvmenv: error: guest script failed (timeout): |
| winring0_v2 | CRASH | bugcheck |  |  | bvmenv: error: guest script failed (timeout): |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| lha | CRASH | bugcheck | guest crashed/hung: power= | docs\lab\20261022-topup-unsafe\raw\lha.log |
| phydmacc | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-topup-unsafe\raw\phydmacc.log |
| winiodrv_b | CRASH | bugcheck | guest crashed/hung: power= | docs\lab\20261022-topup-unsafe\raw\winiodrv_b.log |
| winring0_v2 | CRASH | bugcheck | guest crashed/hung: power= | docs\lab\20261022-topup-unsafe\raw\winring0_v2.log |

## Crashes (VM bugchecks/hangs)

- **lha**: power=; stop_code=n/a; screen=; recovered=True
- **winiodrv_b**: power=; stop_code=n/a; screen=; recovered=True
- **winring0_v2**: power=; stop_code=n/a; screen=; recovered=True

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
