# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: True   unsafe-physical: False
- kdu.exe sha256: d425075feb588bbe3645115f6f439297941ba62ae071bb50e39c0578975e5395   timeout/id: 90s   generated: 2026-10-22T09:50:41.6346243+08:00

**118 exploit(s): 34 PASS, 61 FAIL, 1 CRASH, 0 TIMEOUT, 22 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| adlice_rootlaser | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| aida64 | FAIL | primitive-failed |  |  | FAIL aida64 cannot read ntoskrnl image header |
| alcpu | FAIL | primitive-failed |  |  | FAIL alcpu cannot read ntoskrnl image header |
| amd | FAIL | driver-start-failed |  |  | FAIL amd amd: cannot start service 'AMDRyzenMasterDriver': StartService failed: 连到系统上的设备没有发挥作用。 (0x0000001F) |
| amd_affdriver | FAIL | primitive-failed |  |  | FAIL amd_affdriver cannot read ntoskrnl image header |
| amd_aod215 | FAIL | primitive-failed |  |  | FAIL amd_aod215 cannot read ntoskrnl image header |
| amd_pdfwkrnl | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| appremover | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| appshopdrv103 | FAIL | primitive-failed |  |  | FAIL appshopdrv103 cannot read ntoskrnl image header |
| asr_autochkupd | FAIL | primitive-failed |  |  | FAIL asr_autochkupd cannot read ntoskrnl image header |
| asr_ibdrv | FAIL | primitive-failed |  |  | FAIL asr_ibdrv cannot read ntoskrnl image header |
| asr_omgdrv | FAIL | primitive-failed |  |  | FAIL asr_omgdrv cannot read ntoskrnl image header |
| asr_rapidstart | FAIL | primitive-failed |  |  | FAIL asr_rapidstart cannot read ntoskrnl image header |
| asrdrv10 | FAIL | primitive-failed |  |  | FAIL asrdrv10 cannot read ntoskrnl image header |
| asrdrv106 | FAIL | primitive-failed |  |  | FAIL asrdrv106 cannot read ntoskrnl image header |
| asrdrv107 | FAIL | primitive-failed |  |  | FAIL asrdrv107 cannot read ntoskrnl image header |
| asrdrv109 | FAIL | primitive-failed |  |  | FAIL asrdrv109 cannot read ntoskrnl image header |
| asrock | FAIL | primitive-failed |  |  | FAIL asrock cannot read ntoskrnl image header |
| astra64 | FAIL | kdu-crashed |  |  | guest exit 0xc0000005 |
| asusio2 | FAIL | device-open-failed |  |  | FAIL asusio2 asusio2: cannot open device '\\.\Asusgio2': CreateFile(\\.\Asusgio2) failed: 拒绝访问。 (0x00000005) |
| asusio3 | FAIL | device-open-failed |  |  | FAIL asusio3 asusio3: cannot open device '\\.\Asusgio3': CreateFile(\\.\Asusgio3) failed: 拒绝访问。 (0x00000005) |
| atszio64 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| atszio64_v1 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| axtudrv | FAIL | primitive-failed |  |  | FAIL axtudrv cannot read ntoskrnl image header |
| bdapiutil | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| binalyze_irec | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| ccprotect | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| chr34x05 | FAIL | service-create-failed |  |  | FAIL chr34x05 chr34x05: cannot create service 'CHR34X05': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| cormem | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| cormem_v1 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| cormem_v2 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| cormem_v3 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| cormem_v4 | FAIL | primitive-failed |  |  | FAIL cormem_v4 cannot read ntoskrnl image header |
| dbk64 | FAIL | driver-start-failed |  |  | FAIL dbk64 dbk64: cannot start service 'CEDRIVER73': StartService failed: 连到系统上的设备没有发挥作用。 (0x0000001F) (DBK registry-parameter fallback: device \\.\CEDRIVER73 did not appear) |
| dbutil23 | FAIL | service-create-failed |  |  | FAIL dbutil23 dbutil23: cannot create service 'DBUtil_2_3': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| dbutildrv2 | FAIL | service-create-failed |  |  | FAIL dbutildrv2 dbutildrv2: cannot create service 'DBUtilDrv2': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| directio_v2 | FAIL | device-open-failed |  |  | FAIL directio_v2 directio_v2: cannot open device '\\.\LoopLpt;\\.\DIRECTIO64': device \\.\DIRECTIO64 did not appear |
| directio64 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| directio64_2 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| directio64_v1 | FAIL | device-open-failed |  |  | FAIL directio64_v1 directio64_v1: cannot open device '\\.\DIRECTIO64': device \\.\DIRECTIO64 did not appear |
| echodrv | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| ene2 | FAIL | device-open-failed |  |  | FAIL ene2 ene2: cannot open device '\\.\EneTechIo': CreateFile(\\.\EneTechIo) failed: 拒绝访问。 (0x00000005) |
| eneio64 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| enetechio64 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| enportv | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| evga_eleetx1 | FAIL | primitive-failed |  |  | FAIL evga_eleetx1 cannot read ntoskrnl image header |
| exarmpio | FAIL | service-create-failed |  |  | FAIL exarmpio exarmpio: cannot create service 'exarmpio': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| gamedriverx64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| gdrv | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| glckio2 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| gmer | FAIL | blocked-revoked |  |  | FAIL gmer gmer: cannot start service 'gmerdrv': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |
| goflydrv | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| honos2ec | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| hp_etdsupport | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| hp_hpwks | FAIL | primitive-failed |  |  | FAIL hp_hpwks cannot read ntoskrnl image header |
| hwaudioos2ec | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| hwrwdrv | FAIL | primitive-failed |  |  | FAIL hwrwdrv cannot read ntoskrnl image header |
| inpoutx64 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| intel_nal | FAIL | primitive-failed |  |  | FAIL intel_nal cannot read ntoskrnl image header |
| intel_pmxdrv | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| ipctype | FAIL | primitive-failed |  |  | FAIL ipctype cannot read ntoskrnl image header |
| k7rkscan1516 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| k7rkscan2310 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| kph | FAIL | device-open-failed |  |  | FAIL kph kph: cannot open device '\?\GLOBALROOT\Device\KProcessHacker2': CreateFile(\?\GLOBALROOT\Device\KProcessHacker2) failed: 文件名、目录名或卷标语法不正确。 (0x0000007B) |
| ksapi64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| ktapi | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| ktapi_v1 | PASS |  | driver | 0xfffff807d4200000 | ntoskrnl=0xfffff807d4200000 backend=driver |
| leco | FAIL | primitive-failed |  |  | FAIL leco cannot read ntoskrnl image header |
| lenovo_ldd | FAIL | primitive-failed |  |  | FAIL lenovo_ldd cannot read ntoskrnl image header |
| lenovo_msrio | CRASH | bugcheck |  |  | bvmenv: error: guest script failed (timeout): |
| lha | FAIL | primitive-failed |  |  | FAIL lha cannot read ntoskrnl image header |
| libwasys | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| marvinhw | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| matrox | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| mhyprot2 | FAIL | blocked-revoked |  |  | FAIL mhyprot2 mhyprot2: cannot start service 'mhyprot2': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |
| mil1553b | FAIL | service-create-failed |  |  | FAIL mil1553b mil1553b: cannot create service 'MIL1553B': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| mimidrv | FAIL | blocked-revoked |  |  | FAIL mimidrv mimidrv: cannot start service 'mimidrv': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |
| monprocessex | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| msio64 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| netease_neacsafe | FAIL | fail-other |  |  | FAIL netease_neacsafe netease_neacsafe: NeacSafe64 service did not start (state=1, exit=2, start error=系统找不到指定的文件。 (0x00000002)) |
| nseckrnl | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| nvidia_nvoclock | FAIL | primitive-failed |  |  | FAIL nvidia_nvoclock cannot read ntoskrnl image header |
| pctcore64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| pgrhostcontrol | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| phydmacc | FAIL | primitive-failed |  |  | FAIL phydmacc cannot read ntoskrnl image header |
| physmem64 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| procexp | FAIL | primitive-failed |  |  | FAIL procexp procexp: no \Device\PhysicalMemory section handle found (handles=43510, candidates=4679, duplicate_failures=590, name_misses=4089) |
| procexp1702 | FAIL | primitive-failed |  |  | FAIL procexp1702 procexp1702: the System process has no \Device\PhysicalMemory section handle |
| rtcore64 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| rtkio64 | FAIL | primitive-failed |  |  | FAIL rtkio64 cannot read ntoskrnl image header |
| rtkio64_2 | FAIL | primitive-failed |  |  | FAIL rtkio64_2 cannot read ntoskrnl image header |
| rtkiow10x64 | FAIL | primitive-failed |  |  | FAIL rtkiow10x64 cannot read ntoskrnl image header |
| rtkiow8x64 | FAIL | primitive-failed |  |  | FAIL rtkiow8x64 cannot read ntoskrnl image header |
| rzpnk | FAIL | primitive-failed |  |  | FAIL rzpnk rzpnk: no \Device\PhysicalMemory section handle found in the System process (handles=43241, candidates=4677, duplicate_failures=275, name_misses=4402) |
| seacom_xr | FAIL | service-create-failed |  |  | FAIL seacom_xr seacom_xr: cannot create service 'SeaCOM-XR': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| ser15x | FAIL | service-create-failed |  |  | FAIL ser15x ser15x: cannot create service 'ser15x': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| sivx64 | FAIL | device-open-failed |  |  | FAIL sivx64 sivx64: cannot open device '\\.\Global\SIVDRIVER;\\.\SIVDRIVER;\\.\GLOBALROOT\Device\SIVDRIVER': CreateFile(\\.\GLOBALROOT\Device\SIVDRIVER) failed: 拒绝访问。 (0x00000005); fallback: SIVDRIVER is present but not accessible with any access mask (create/start succeeded) |
| stprocessmonitor114 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| stprocessmonitor2618 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| sysdrv3s | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| tfsysmon | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| tpup_throttlestop | FAIL | primitive-failed |  |  | FAIL tpup_throttlestop cannot read ntoskrnl image header |
| tpw | FAIL | primitive-failed |  |  | FAIL tpw cannot read ntoskrnl image header |
| truesight | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| unknown_eb | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| viragt64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| winhwdrv | FAIL | primitive-failed |  |  | FAIL winhwdrv cannot read ntoskrnl image header |
| winio_a | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| winio64 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| winio64_2 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| winiodrv_a | FAIL | primitive-failed |  |  | FAIL winiodrv_a cannot read ntoskrnl image header |
| winiodrv_b | FAIL | primitive-failed |  |  | FAIL winiodrv_b cannot read ntoskrnl image header |
| winring0 | FAIL | primitive-failed |  |  | FAIL winring0 cannot read ntoskrnl image header |
| wnbios | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| wnbios_2 | PASS |  | driver | 0xfffff801a1200000 | ntoskrnl=0xfffff801a1200000 backend=driver |
| wsftprm | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| xkpsm | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| zodiacon_kobexp | FAIL | device-open-failed |  |  | FAIL zodiacon_kobexp zodiacon_kobexp: cannot open device '\\.\KObjExp': CreateFile(\\.\KObjExp) failed: 拒绝访问。 (0x00000005) |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| aida64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\aida64.log |
| alcpu | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\alcpu.log |
| amd | FAIL | driver-start-failed | driver failed to start (StartService); inspect the raw error code | docs\lab\20261022-final-all\raw\amd.log |
| amd_affdriver | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\amd_affdriver.log |
| amd_aod215 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\amd_aod215.log |
| appshopdrv103 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\appshopdrv103.log |
| asr_autochkupd | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asr_autochkupd.log |
| asr_ibdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asr_ibdrv.log |
| asr_omgdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asr_omgdrv.log |
| asr_rapidstart | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asr_rapidstart.log |
| asrdrv10 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asrdrv10.log |
| asrdrv106 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asrdrv106.log |
| asrdrv107 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asrdrv107.log |
| asrdrv109 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asrdrv109.log |
| asrock | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\asrock.log |
| astra64 | FAIL | kdu-crashed | kdu.exe terminated with exception 0xc0000005; exploit ioctl path crashed user mode | docs\lab\20261022-final-all\raw\astra64.log |
| asusio2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\asusio2.log |
| asusio3 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\asusio3.log |
| axtudrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\axtudrv.log |
| chr34x05 | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-all\raw\chr34x05.log |
| cormem_v4 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\cormem_v4.log |
| dbk64 | FAIL | driver-start-failed | driver failed to start (StartService); inspect the raw error code | docs\lab\20261022-final-all\raw\dbk64.log |
| dbutil23 | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-all\raw\dbutil23.log |
| dbutildrv2 | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-all\raw\dbutildrv2.log |
| directio_v2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\directio_v2.log |
| directio64_v1 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\directio64_v1.log |
| ene2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\ene2.log |
| evga_eleetx1 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\evga_eleetx1.log |
| exarmpio | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-all\raw\exarmpio.log |
| gmer | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-final-all\raw\gmer.log |
| hp_hpwks | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\hp_hpwks.log |
| hwrwdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\hwrwdrv.log |
| intel_nal | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\intel_nal.log |
| ipctype | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\ipctype.log |
| kph | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\kph.log |
| leco | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\leco.log |
| lenovo_ldd | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\lenovo_ldd.log |
| lenovo_msrio | CRASH | bugcheck | guest crashed/hung: power= | docs\lab\20261022-final-all\raw\lenovo_msrio.log |
| lha | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\lha.log |
| mhyprot2 | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-final-all\raw\mhyprot2.log |
| mil1553b | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-all\raw\mil1553b.log |
| mimidrv | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-final-all\raw\mimidrv.log |
| netease_neacsafe | FAIL | fail-other | unclassified failure; see raw log | docs\lab\20261022-final-all\raw\netease_neacsafe.log |
| nvidia_nvoclock | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\nvidia_nvoclock.log |
| phydmacc | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\phydmacc.log |
| procexp | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\procexp.log |
| procexp1702 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\procexp1702.log |
| rtkio64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\rtkio64.log |
| rtkio64_2 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\rtkio64_2.log |
| rtkiow10x64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\rtkiow10x64.log |
| rtkiow8x64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\rtkiow8x64.log |
| rzpnk | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\rzpnk.log |
| seacom_xr | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-all\raw\seacom_xr.log |
| ser15x | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-all\raw\ser15x.log |
| sivx64 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\sivx64.log |
| tpup_throttlestop | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\tpup_throttlestop.log |
| tpw | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\tpw.log |
| winhwdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\winhwdrv.log |
| winiodrv_a | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\winiodrv_a.log |
| winiodrv_b | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\winiodrv_b.log |
| winring0 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-all\raw\winring0.log |
| zodiacon_kobexp | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-all\raw\zodiacon_kobexp.log |

## Crashes (VM bugchecks/hangs)

- **lenovo_msrio**: power=; stop_code=n/a; screen=; recovered=True

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
