# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: True   unsafe-physical: False
- kdu.exe sha256: 538548fe1464f19fa48b62347f69e4a21fea0178570f5286eccf7a1b8c04fc40   timeout/id: 90s   generated: 2026-10-22T05:58:06.9716576+08:00

**2 exploit(s): 2 PASS, 0 FAIL, 0 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| ktapi | PASS |  | driver | 0xfffff803a2400000 | ntoskrnl=0xfffff803a2400000 backend=driver |
| rtcore64 | PASS |  | driver | 0xfffff803a2400000 | ntoskrnl=0xfffff803a2400000 backend=driver |

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
