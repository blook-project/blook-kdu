# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: unknown   testsigning: False   unsafe-physical: False
- kdu.exe sha256: 0ba102832b7ac3ae6f512f194cfc6798f02410a66168872a0341755686d8b09e   timeout/id: 90s   generated: 2026-10-22T08:41:40.7793513+08:00

**2 exploit(s): 1 PASS, 1 FAIL, 0 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| astra64 | FAIL | kdu-crashed |  |  | guest exit 0xc0000005 |
| ktapi | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| astra64 | FAIL | kdu-crashed | kdu.exe terminated with exception 0xc0000005; exploit ioctl path crashed user mode | docs\lab\20261022-harness-verify\raw\astra64.log |

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
