# blook-kdu VM exploit matrix (vm-byovd)

5 exploit(s): **3 PASS**, 2 FAIL. testsigning=True

| id | driver | status | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| ktapi |  | PASS | driver | 0xfffff803cf200000 | PASS ktapi            ntoskrnl=0xfffff803cf200000 backend=driver |
| rtcore64 |  | PASS | driver | 0xfffff803cf200000 | PASS rtcore64         ntoskrnl=0xfffff803cf200000 backend=driver |
| tpw |  | FAIL |  |  | FAIL tpw              cannot read ntoskrnl image header / error exploit self-test failed |
| truesight |  | PASS | driver | 0xfffff803cf200000 | PASS truesight        ntoskrnl=0xfffff803cf200000 backend=driver |
| winring0 |  | FAIL |  |  | bvmenv: error: guest script failed (timeout): |
