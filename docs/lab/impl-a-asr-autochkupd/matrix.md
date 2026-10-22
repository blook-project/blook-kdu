# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: False   unsafe-physical: False
- kdu.exe sha256: 7a6e4ee244fb5e32cfd2320fcfa87edfe4f884dae341c8d17b30b65c8d313b02   timeout/id: 90s   generated: 2026-10-22T07:20:17.4590976+08:00

**1 exploit(s): 0 PASS, 1 FAIL, 0 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| asr_autochkupd | FAIL | primitive-failed |  |  | FAIL asr_autochkupd cannot read ntoskrnl image header |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| asr_autochkupd | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\impl-a-asr-autochkupd\raw\asr_autochkupd.log |

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
