# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: False   unsafe-physical: False
- kdu.exe sha256: 68875b40ec4ab8657a504a10cd178c7a623fa4c9b14ae80f137e22fd17244234   timeout/id: 90s   generated: 2026-10-22T07:22:48.7825719+08:00

**2 exploit(s): 0 PASS, 2 FAIL, 0 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| asrdrv107 | FAIL | primitive-failed |  |  | FAIL asrdrv107 cannot read ntoskrnl image header |
| axtudrv | FAIL | primitive-failed |  |  | FAIL axtudrv cannot read ntoskrnl image header |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| asrdrv107 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\impl-a-control\raw\asrdrv107.log |
| axtudrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\impl-a-control\raw\axtudrv.log |

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
