# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: True   unsafe-physical: False
- kdu.exe sha256: 95477b6c7f40f36f5c84acb6109d5688ba6245d67881856c52f01637a2b1491b   timeout/id: 90s   generated: 2026-10-22T09:56:32.7701323+08:00

**8 exploit(s): 2 PASS, 6 FAIL, 0 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| cormem_v4 | FAIL | primitive-failed |  |  | FAIL cormem_v4 cannot read ntoskrnl image header |
| dbutil23 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| directio_v2 | FAIL | device-open-failed |  |  | FAIL directio_v2 directio_v2: cannot open device '\\.\LoopLpt;\\.\DIRECTIO64': device \\.\DIRECTIO64 did not appear |
| directio64_v1 | FAIL | device-open-failed |  |  | FAIL directio64_v1 directio64_v1: cannot open device '\\.\DIRECTIO64': device \\.\DIRECTIO64 did not appear |
| hp_etdsupp_v1 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| hp_etdsupp_v2 | FAIL | primitive-failed |  |  | FAIL hp_etdsupp_v2 cannot read ntoskrnl image header |
| kph | FAIL | device-open-failed |  |  | FAIL kph kph: cannot open device '\?\GLOBALROOT\Device\KProcessHacker2': CreateFile(\?\GLOBALROOT\Device\KProcessHacker2) failed: 文件名、目录名或卷标语法不正确。 (0x0000007B) |
| mimidrv | FAIL | blocked-revoked |  |  | FAIL mimidrv mimidrv: cannot start service 'mimidrv': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| cormem_v4 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-topup1\raw\cormem_v4.log |
| directio_v2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-topup1\raw\directio_v2.log |
| directio64_v1 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-topup1\raw\directio64_v1.log |
| hp_etdsupp_v2 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-topup1\raw\hp_etdsupp_v2.log |
| kph | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-topup1\raw\kph.log |
| mimidrv | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-topup1\raw\mimidrv.log |

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
