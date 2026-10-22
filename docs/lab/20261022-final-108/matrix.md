# blook-kdu VM exploit matrix

- vm: vm-byovd   guest: 10.0.26200 build 26200   testsigning: True   unsafe-physical: False
- kdu.exe sha256: 68875b40ec4ab8657a504a10cd178c7a623fa4c9b14ae80f137e22fd17244234   timeout/id: 90s   generated: 2026-10-22T08:00:44.1758928+08:00

**108 exploit(s): 23 PASS, 62 FAIL, 1 CRASH, 0 TIMEOUT, 22 SKIP**

## Results

| id | status | classification | backend | ntoskrnl | detail |
| --- | --- | --- | --- | --- | --- |
| adlice_rootlaser | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| aida64 | FAIL | primitive-failed |  |  | FAIL aida64 cannot read ntoskrnl image header |
| alcpu | FAIL | primitive-failed |  |  | FAIL alcpu cannot read ntoskrnl image header |
| amd | FAIL | driver-start-failed |  |  | FAIL amd amd: cannot start service 'AMDRyzenMasterDriver': StartService failed: 连到系统上的设备没有发挥作用。 (0x0000001F) |
| amd_affdriver | FAIL | primitive-failed |  |  | FAIL amd_affdriver cannot read ntoskrnl image header |
| amd_aod215 | FAIL | primitive-failed |  |  | FAIL amd_aod215 cannot read ntoskrnl image header |
| amd_pdfwkrnl | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
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
| astra64 | FAIL | unparsed |  |  | exit_code    : -1073741819 |
| asusio2 | FAIL | device-open-failed |  |  | FAIL asusio2 asusio2: cannot open device '\\.\Asusgio2': CreateFile(\\.\Asusgio2) failed: 拒绝访问。 (0x00000005) |
| asusio3 | FAIL | device-open-failed |  |  | FAIL asusio3 asusio3: cannot open device '\\.\Asusgio3': CreateFile(\\.\Asusgio3) failed: 拒绝访问。 (0x00000005) |
| atszio64 | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| axtudrv | FAIL | primitive-failed |  |  | FAIL axtudrv cannot read ntoskrnl image header |
| bdapiutil | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| binalyze_irec | FAIL | primitive-failed |  |  | FAIL binalyze_irec cannot read ntoskrnl image header |
| ccprotect | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| chr34x05 | FAIL | service-create-failed |  |  | FAIL chr34x05 chr34x05: cannot create service 'CHR34X05': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| cormem | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| dbk64 | FAIL | driver-start-failed |  |  | FAIL dbk64 dbk64: cannot start service 'CEDRIVER73': StartService failed: 连到系统上的设备没有发挥作用。 (0x0000001F) |
| dbutil23 | FAIL | service-create-failed |  |  | FAIL dbutil23 dbutil23: cannot create service 'DBUtil_2_3': CreateService failed: 指定的服务已标记为删除。 (0x00000430) |
| dbutildrv2 | FAIL | device-open-failed |  |  | FAIL dbutildrv2 dbutildrv2: cannot open device '\\.\DBUtil_2_5': device \\.\DBUtil_2_5 did not appear |
| directio64 | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| directio64_2 | FAIL | driver-start-failed |  |  | FAIL directio64_2 directio64_2: cannot start service 'DirectIo64_2': StartService failed: 参数错误。 (0x00000057) |
| echodrv | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| eneio64 | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| enetechio64 | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| enportv | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| evga_eleetx1 | FAIL | primitive-failed |  |  | FAIL evga_eleetx1 cannot read ntoskrnl image header |
| exarmpio | FAIL | device-open-failed |  |  | FAIL exarmpio exarmpio: cannot open device '\\.\ComGPIO;\\.\GLOBALROOT\Device\ComGPIO': device \\.\GLOBALROOT\Device\ComGPIO did not appear |
| gamedriverx64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| gdrv | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| glckio2 | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| gmer | FAIL | blocked-revoked |  |  | FAIL gmer gmer: cannot start service 'gmerdrv': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |
| goflydrv | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| honos2ec | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| hp_etdsupport | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| hp_hpwks | FAIL | primitive-failed |  |  | FAIL hp_hpwks cannot read ntoskrnl image header |
| hwaudioos2ec | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| hwrwdrv | FAIL | primitive-failed |  |  | FAIL hwrwdrv cannot read ntoskrnl image header |
| inpoutx64 | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| intel_nal | FAIL | primitive-failed |  |  | FAIL intel_nal cannot read ntoskrnl image header |
| intel_pmxdrv | FAIL | primitive-failed |  |  | FAIL intel_pmxdrv cannot read ntoskrnl image header |
| ipctype | FAIL | primitive-failed |  |  | FAIL ipctype cannot read ntoskrnl image header |
| k7rkscan1516 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| k7rkscan2310 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| kph | FAIL | fail-other |  |  | FAIL kph kph: kph supports Windows build 19044 at most (current 26200) |
| ksapi64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| ktapi | PASS |  | driver | 0xfffff800c8800000 | ntoskrnl=0xfffff800c8800000 backend=driver |
| leco | FAIL | primitive-failed |  |  | FAIL leco cannot read ntoskrnl image header |
| lenovo_ldd | FAIL | primitive-failed |  |  | FAIL lenovo_ldd cannot read ntoskrnl image header |
| lenovo_msrio | CRASH | bugcheck |  |  | bvmenv: error: guest script failed (timeout): |
| lha | FAIL | primitive-failed |  |  | FAIL lha cannot read ntoskrnl image header |
| libwasys | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| marvinhw | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| matrox | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| mhyprot2 | FAIL | blocked-revoked |  |  | FAIL mhyprot2 mhyprot2: cannot start service 'mhyprot2': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |
| mil1553b | FAIL | device-open-failed |  |  | FAIL mil1553b mil1553b: cannot open device '\\.\CHR31X1X-A;\\.\GLOBALROOT\Device\CHR31X1X-A': device \\.\GLOBALROOT\Device\CHR31X1X-A did not appear |
| mimidrv | FAIL | blocked-revoked |  |  | FAIL mimidrv mimidrv: cannot start service 'mimidrv': StartService failed: 证书已被颁发者直接吊销。 (0x800B010C) |
| monprocessex | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| msio64 | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| netease_neacsafe | FAIL | fail-other |  |  | FAIL netease_neacsafe netease_neacsafe: NeacSafe64 service did not start (state=1, exit=2, start error=系统找不到指定的文件。 (0x00000002)) |
| nseckrnl | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| nvidia_nvoclock | FAIL | primitive-failed |  |  | FAIL nvidia_nvoclock cannot read ntoskrnl image header |
| pctcore64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| pgrhostcontrol | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| physmem64 | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| procexp | FAIL | primitive-failed |  |  | FAIL procexp procexp: the System process has no \Device\PhysicalMemory section handle |
| procexp1702 | FAIL | primitive-failed |  |  | FAIL procexp1702 procexp1702: the System process has no \Device\PhysicalMemory section handle |
| rtcore64 | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| rtkio64 | FAIL | primitive-failed |  |  | FAIL rtkio64 cannot read ntoskrnl image header |
| rtkiow10x64 | FAIL | primitive-failed |  |  | FAIL rtkiow10x64 cannot read ntoskrnl image header |
| rtkiow8x64 | FAIL | primitive-failed |  |  | FAIL rtkiow8x64 cannot read ntoskrnl image header |
| rzpnk | FAIL | primitive-failed |  |  | FAIL rzpnk rzpnk: the System process has no \Device\PhysicalMemory section handle |
| seacom_xr | FAIL | device-open-failed |  |  | FAIL seacom_xr seacom_xr: cannot open device '\\.\GLOBALROOT\Device\seacomxr;\\.\seacomxr': device \\.\seacomxr did not appear |
| ser15x | FAIL | device-open-failed |  |  | FAIL ser15x ser15x: cannot open device '\\.\ser15x;\\.\GLOBALROOT\Device\ser15x': device \\.\GLOBALROOT\Device\ser15x did not appear |
| sivx64 | FAIL | device-open-failed |  |  | FAIL sivx64 sivx64: cannot open device '\\.\Global\SIVDRIVER;\\.\SIVDRIVER;\\.\GLOBALROOT\Device\SIVDRIVER': CreateFile(\\.\GLOBALROOT\Device\SIVDRIVER) failed: 拒绝访问。 (0x00000005) |
| stprocessmonitor114 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| stprocessmonitor2618 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| sysdrv3s | FAIL | primitive-failed |  |  | FAIL sysdrv3s cannot read ntoskrnl image header |
| tfsysmon | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| tpup_throttlestop | FAIL | primitive-failed |  |  | FAIL tpup_throttlestop cannot read ntoskrnl image header |
| tpw | FAIL | primitive-failed |  |  | FAIL tpw cannot read ntoskrnl image header |
| truesight | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| unknown_eb | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| usassaio | FAIL | primitive-failed |  |  | FAIL usassaio cannot read ntoskrnl image header |
| usassaio_sci | FAIL | primitive-failed |  |  | FAIL usassaio_sci cannot read ntoskrnl image header |
| usassaio_v2 | FAIL | primitive-failed |  |  | FAIL usassaio_v2 cannot read ntoskrnl image header |
| viragt64 | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| winhwdrv | FAIL | primitive-failed |  |  | FAIL winhwdrv cannot read ntoskrnl image header |
| winio64 | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| winio64_2 | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| winiodrv_a | FAIL | primitive-failed |  |  | FAIL winiodrv_a cannot read ntoskrnl image header |
| winiodrv_b | FAIL | primitive-failed |  |  | FAIL winiodrv_b cannot read ntoskrnl image header |
| winring0 | FAIL | primitive-failed |  |  | FAIL winring0 cannot read ntoskrnl image header |
| wnbios | PASS |  | driver | 0xfffff804ed800000 | ntoskrnl=0xfffff804ed800000 backend=driver |
| wsftprm | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| xkpsm | SKIP | skipped-no-primitive |  |  | kill-only driver (no memory primitive; self-test N/A) |
| zodiacon_kobexp | FAIL | device-open-failed |  |  | FAIL zodiacon_kobexp zodiacon_kobexp: cannot open device '\\.\KObjExp': CreateFile(\\.\KObjExp) failed: 拒绝访问。 (0x00000005) |

## Actionable failures

| id | status | classification | likely cause | raw |
| --- | --- | --- | --- | --- |
| aida64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\aida64.log |
| alcpu | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\alcpu.log |
| amd | FAIL | driver-start-failed | driver failed to start (StartService); inspect the raw error code | docs\lab\20261022-final-108\raw\amd.log |
| amd_affdriver | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\amd_affdriver.log |
| amd_aod215 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\amd_aod215.log |
| appshopdrv103 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\appshopdrv103.log |
| asr_autochkupd | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asr_autochkupd.log |
| asr_ibdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asr_ibdrv.log |
| asr_omgdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asr_omgdrv.log |
| asr_rapidstart | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asr_rapidstart.log |
| asrdrv10 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asrdrv10.log |
| asrdrv106 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asrdrv106.log |
| asrdrv107 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asrdrv107.log |
| asrdrv109 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asrdrv109.log |
| asrock | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\asrock.log |
| astra64 | FAIL | unparsed | no PASS/FAIL line in the guest output | docs\lab\20261022-final-108\raw\astra64.log |
| asusio2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\asusio2.log |
| asusio3 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\asusio3.log |
| axtudrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\axtudrv.log |
| binalyze_irec | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\binalyze_irec.log |
| chr34x05 | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-108\raw\chr34x05.log |
| dbk64 | FAIL | driver-start-failed | driver failed to start (StartService); inspect the raw error code | docs\lab\20261022-final-108\raw\dbk64.log |
| dbutil23 | FAIL | service-create-failed | SCM refused the service; stale service or path problem | docs\lab\20261022-final-108\raw\dbutil23.log |
| dbutildrv2 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\dbutildrv2.log |
| directio64_2 | FAIL | driver-start-failed | driver failed to start (StartService); inspect the raw error code | docs\lab\20261022-final-108\raw\directio64_2.log |
| evga_eleetx1 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\evga_eleetx1.log |
| exarmpio | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\exarmpio.log |
| gmer | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-final-108\raw\gmer.log |
| hp_hpwks | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\hp_hpwks.log |
| hwrwdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\hwrwdrv.log |
| intel_nal | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\intel_nal.log |
| intel_pmxdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\intel_pmxdrv.log |
| ipctype | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\ipctype.log |
| kph | FAIL | fail-other | unclassified failure; see raw log | docs\lab\20261022-final-108\raw\kph.log |
| leco | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\leco.log |
| lenovo_ldd | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\lenovo_ldd.log |
| lenovo_msrio | CRASH | bugcheck | guest crashed/hung: bvmenv state unavailable (guest unresponsive/hung) | docs\lab\20261022-final-108\raw\lenovo_msrio.log |
| lha | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\lha.log |
| mhyprot2 | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-final-108\raw\mhyprot2.log |
| mil1553b | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\mil1553b.log |
| mimidrv | FAIL | blocked-revoked | signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective | docs\lab\20261022-final-108\raw\mimidrv.log |
| netease_neacsafe | FAIL | fail-other | unclassified failure; see raw log | docs\lab\20261022-final-108\raw\netease_neacsafe.log |
| nvidia_nvoclock | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\nvidia_nvoclock.log |
| procexp | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\procexp.log |
| procexp1702 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\procexp1702.log |
| rtkio64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\rtkio64.log |
| rtkiow10x64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\rtkiow10x64.log |
| rtkiow8x64 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\rtkiow8x64.log |
| rzpnk | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\rzpnk.log |
| seacom_xr | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\seacom_xr.log |
| ser15x | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\ser15x.log |
| sivx64 | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\sivx64.log |
| sysdrv3s | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\sysdrv3s.log |
| tpup_throttlestop | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\tpup_throttlestop.log |
| tpw | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\tpw.log |
| usassaio | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\usassaio.log |
| usassaio_sci | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\usassaio_sci.log |
| usassaio_v2 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\usassaio_v2.log |
| winhwdrv | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\winhwdrv.log |
| winiodrv_a | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\winiodrv_a.log |
| winiodrv_b | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\winiodrv_b.log |
| winring0 | FAIL | primitive-failed | driver loaded but the kernel memory primitive failed (ioctl/translation) | docs\lab\20261022-final-108\raw\winring0.log |
| zodiacon_kobexp | FAIL | device-open-failed | driver loaded but its device/IOCTL path did not open; ioctl/device-name bug | docs\lab\20261022-final-108\raw\zodiacon_kobexp.log |

## Crashes (VM bugchecks/hangs)

- **lenovo_msrio**: bvmenv state unavailable (guest unresponsive/hung); stop_code=n/a; screen=; recovered=True

## How to consume this matrix

- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.
- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).
- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.
