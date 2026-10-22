# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: True   unsafe-physical: False
- kdu.exe sha256: cbb66e01914c57e0b862fc890ca895a028412c53b8afb6d1c46a9ce79ce97cf5   timeout/id: 90s   generated: 2026-10-22T08:56:25.1790774+08:00

**33 exploit(s): 7 PASS, 26 FAIL, 0 CRASH, 0 TIMEOUT, 0 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| aida64 | FAIL | primitive-failed |  |  | FAIL aida64 cannot read ntoskrnl image header |
| amd_affdriver | FAIL | primitive-failed |  |  | FAIL amd_affdriver cannot read ntoskrnl image header |
| amd_aod215 | FAIL | primitive-failed |  |  | FAIL amd_aod215 cannot read ntoskrnl image header |
| appshopdrv103 | FAIL | primitive-failed |  |  | FAIL appshopdrv103 cannot read ntoskrnl image header |
| atszio64_v1 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| chr34x05 | FAIL | service-create-failed |  |  | FAIL chr34x05 chr34x05: cannot create service 'CHR34X05': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| cormem_v1 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| cormem_v2 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| cormem_v3 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| cormem_v4 | FAIL | primitive-failed |  |  | FAIL cormem_v4 cannot read ntoskrnl image header |
| dbk64 | FAIL | driver-start-failed |  |  | FAIL dbk64 dbk64: cannot start service 'CEDRIVER73': StartService failed: 连到系统上的设备没有发挥作用。 (0x0000001F) (DBK registry-parameter fallback: device \\.\CEDRIVER73 did not appear) |
| directio_v2 | FAIL | device-open-failed |  |  | FAIL directio_v2 directio_v2: cannot open device '\\.\LoopLpt;\\.\DIRECTIO64': device \\.\DIRECTIO64 did not appear |
| directio64_v1 | FAIL | device-open-failed |  |  | FAIL directio64_v1 directio64_v1: cannot open device '\\.\DIRECTIO64': device \\.\DIRECTIO64 did not appear |
| ene2 | FAIL | device-open-failed |  |  | FAIL ene2 ene2: cannot open device '\\.\EneTechIo': CreateFile(\\.\EneTechIo) failed: 拒绝访问。 (0x00000005) |
| hwrwdrv | FAIL | primitive-failed |  |  | FAIL hwrwdrv cannot read ntoskrnl image header |
| intel_nal | FAIL | primitive-failed |  |  | FAIL intel_nal cannot read ntoskrnl image header |
| ipctype | FAIL | primitive-failed |  |  | FAIL ipctype cannot read ntoskrnl image header |
| kph | FAIL | device-open-failed |  |  | FAIL kph kph: cannot open device '\?\GLOBALROOT\Device\KProcessHacker2': CreateFile(\?\GLOBALROOT\Device\KProcessHacker2) failed: 文件名、目录名或卷标语法不正确。 (0x0000007B) |
| ktapi_v1 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| leco | FAIL | primitive-failed |  |  | FAIL leco cannot read ntoskrnl image header |
| mimidrv | FAIL | blocked-revoked |  |  | FAIL mimidrv mimidrv: cannot start service 'mimidrv': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |
| netease_neacsafe | FAIL | fail-other |  |  | FAIL netease_neacsafe netease_neacsafe: NeacSafe64 service did not start (state=1, exit=2, start error=系统找不到指定的文件。 (0x00000002)) |
| nvidia_nvoclock | FAIL | primitive-failed |  |  | FAIL nvidia_nvoclock cannot read ntoskrnl image header |
| phydmacc | FAIL | primitive-failed |  |  | FAIL phydmacc cannot read ntoskrnl image header |
| procexp | FAIL | primitive-failed |  |  | FAIL procexp procexp: no \Device\PhysicalMemory section handle found (handles=41552, candidates=4501, duplicate_failures=590, name_misses=3911) |
| procexp1702 | FAIL | primitive-failed |  |  | FAIL procexp1702 procexp1702: the System process has no \Device\PhysicalMemory section handle |
| rzpnk | FAIL | primitive-failed |  |  | FAIL rzpnk rzpnk: no \Device\PhysicalMemory section handle found in the System process (handles=41707, candidates=4543, duplicate_failures=261, name_misses=4282) |
| sivx64 | FAIL | device-open-failed |  |  | FAIL sivx64 sivx64: cannot open device '\\.\Global\SIVDRIVER;\\.\SIVDRIVER;\\.\GLOBALROOT\Device\SIVDRIVER': CreateFile(\\.\GLOBALROOT\Device\SIVDRIVER) failed: 拒绝访问。 (0x00000005); fallback: SIVDRIVER is present but not accessible with any access mask (create/start succeeded) |
| sysdrv3s | FAIL | service-create-failed |  |  | FAIL sysdrv3s sysdrv3s: cannot create service 'SysDrv3S': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| tpup_throttlestop | FAIL | primitive-failed |  |  | FAIL tpup_throttlestop cannot read ntoskrnl image header |
| winhwdrv | FAIL | primitive-failed |  |  | FAIL winhwdrv cannot read ntoskrnl image header |
| winio_a | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| wnbios_2 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| aida64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\aida64.log |
| amd_affdriver | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\amd_affdriver.log |
| amd_aod215 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\amd_aod215.log |
| appshopdrv103 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\appshopdrv103.log |
| chr34x05 | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-fixbatch5\raw\chr34x05.log |
| cormem_v4 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\cormem_v4.log |
| dbk64 | FAIL | driver-start-failed | driver failed to start (StartService); inspect the raw error code | docs\lab\20261022-fixbatch5\raw\dbk64.log |
| directio_v2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-fixbatch5\raw\directio_v2.log |
| directio64_v1 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-fixbatch5\raw\directio64_v1.log |
| ene2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-fixbatch5\raw\ene2.log |
| hwrwdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\hwrwdrv.log |
| intel_nal | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\intel_nal.log |
| ipctype | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\ipctype.log |
| kph | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-fixbatch5\raw\kph.log |
| leco | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\leco.log |
| mimidrv | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-fixbatch5\raw\mimidrv.log |
| netease_neacsafe | FAIL | fail-other | unclassified failure; see raw log | docs\lab\20261022-fixbatch5\raw\netease_neacsafe.log |
| nvidia_nvoclock | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\nvidia_nvoclock.log |
| phydmacc | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\phydmacc.log |
| procexp | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\procexp.log |
| procexp1702 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\procexp1702.log |
| rzpnk | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\rzpnk.log |
| sivx64 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-fixbatch5\raw\sivx64.log |
| sysdrv3s | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-fixbatch5\raw\sysdrv3s.log |
| tpup_throttlestop | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\tpup_throttlestop.log |
| winhwdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-fixbatch5\raw\winhwdrv.log |

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
