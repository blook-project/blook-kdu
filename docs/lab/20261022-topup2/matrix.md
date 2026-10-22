# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: True   unsafe-physical: False
- kdu.exe sha256: 34cecd98c67b934acd1e7110bcb2dccbbd582638ac333fd9793ccbf5c4a74a99   timeout/id: 90s   generated: 2026-10-22T10:02:14.2282712+08:00

**2 exploit(s): 0 PASS, 2 FAIL, 0 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| chr34x05 | FAIL | service-create-failed |  |  | FAIL chr34x05 chr34x05: cannot create service 'CHR34X05': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| kph | FAIL | primitive-failed |  |  | FAIL kph cannot read ntoskrnl image header |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| chr34x05 | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-topup2\raw\chr34x05.log |
| kph | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-topup2\raw\kph.log |

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
