# blook-kdu: VM lab matrix runner.
#
# Verifies each compiled exploit by actually loading its driver and running
# `kdu exploits test <id>` inside a disposable bvmenv guest. The host never
# loads a driver: only the guest (a throwaway VM) ever touches kernel code.
#
#   pwsh scripts/vm-lab.ps1 -All                           # every exploit
#   pwsh scripts/vm-lab.ps1 -Ids rtcore64,ktapi            # a subset
#   pwsh scripts/vm-lab.ps1 -All -TestSigning             # enable lab test signing first
#   pwsh scripts/vm-lab.ps1 -Ids x -NoPush -NoSign         # reuse staged VM state
#   pwsh scripts/vm-lab.ps1 -All -UnsafePhysical           # lab-only: allow unsafe-hole page walks
#
# Lab model: the vendor images are revoked/blocklisted by current Microsoft
# policy, so every driver blob is re-signed with the bundled legacy SPC test
# certificate and the guest is switched to test signing (lab-only). The embedded
# release binaries are never modified - only build/generated/signed-drivers.
#
# Readiness for scale: signing is cached by SHA256, the bundle is pushed once per
# VM boot, per-id work is one elevated guest exec, and a crash only costs one
# reset (+ one lab-config reboot). A global named mutex serializes guest
# operations so parallel implementers can call this script concurrently
# (`-Ids <one id>`).
[CmdletBinding()]
param(
    [string] $Vm = 'vm-byovd',
    [string[]] $Ids = @(),
    [switch] $All,
    [string] $Out = '',
    [switch] $NoSign,
    [switch] $NoPush,
    [switch] $NoPrepare,
    [switch] $NoReset,
    [switch] $TestSigning,
    [switch] $UnsafePhysical,
    [switch] $ForceSign,
    [switch] $RetryFailed,
    [int] $TimeoutSeconds = 90,
    [int] $BatchLogEvery = 10,
    [Alias('Result')][string] $MergeResult = '',
    [string] $Root = (Split-Path -Parent $PSScriptRoot),
    [string] $Bvmenv = 'D:\blook-kernel-project\blook-vmware-environment\build\windows\x64\release\bvmenv.exe'
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Root).Path
Set-Location $Root
if (-not $All) {
    $Ids = @($Ids | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ })
}
if (-not $All -and -not $RetryFailed -and $Ids.Count -eq 0) {
    throw 'pass -All, -Ids <id1,id2,...>, or -RetryFailed'
}
if (-not (Test-Path $Bvmenv)) { throw "bvmenv not found: $Bvmenv" }
if (-not $Out) {
    $Out = Join-Path $Root ("docs/lab/{0}-vm" -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
New-Item -ItemType Directory -Force $Out | Out-Null
New-Item -ItemType Directory -Force (Join-Path $Out 'raw') | Out-Null
$logPath = Join-Path $Out 'pipeline.log'
$script:Bvmenv = $Bvmenv
$script:Vm = $Vm
$script:Out = $Out
$script:TestSigning = [bool]$TestSigning
$script:UnsafePhysical = [bool]$UnsafePhysical
$script:KduExe = Join-Path $Root 'build/windows/x64/release/kdu.exe'
$script:SignedDir = Join-Path $Root 'build/generated/signed-drivers'
$script:CertDir = Join-Path $Root 'build/generated/certs'
$script:ExitCode = 0

function Log([string] $message) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $message
    Write-Host $line
    Add-Content -LiteralPath $logPath -Value $line -Encoding utf8
}

$mutex = New-Object System.Threading.Mutex($false, 'Global\blook-kdu-vmlab')
$owned = $false
try {
    try {
        $owned = $mutex.WaitOne([TimeSpan]::FromSeconds(3600))
    } catch [System.Threading.AbandonedMutexException] {
        # A previous runner died while holding the mutex (killed turn/crash):
        # the wait still acquired ownership, so continue normally.
        $owned = $true
        Log 'recovered an abandoned VM lab mutex (previous runner died)'
    }
    if (-not $owned) { throw 'timed out waiting for the VM lab mutex' }
    Log "vm lab start: vm=$Vm out=$Out all=$All ids=$($Ids -join ',') testsigning=$TestSigning unsafe=$UnsafePhysical"

    # -----------------------------------------------------------------------
    # bvmenv / guest helpers
    # -----------------------------------------------------------------------
    function Invoke-Bvmenv {
        param([string[]] $Arguments, [int] $Timeout = 300)
        $stdout = Join-Path $env:TEMP ("bvmenv-{0}.out" -f [guid]::NewGuid())
        $stderr = Join-Path $env:TEMP ("bvmenv-{0}.err" -f [guid]::NewGuid())
        $process = Start-Process -FilePath $script:Bvmenv -ArgumentList $Arguments `
            -NoNewWindow -PassThru -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr
        if (-not $process.WaitForExit($Timeout * 1000)) {
            try { $process.Kill($true) } catch { }
            Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
            return @{ code = 124; stdout = ''; stderr = "timeout after ${Timeout}s" }
        }
        $outText = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
        $errText = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
        Remove-Item $stdout, $stderr -Force -ErrorAction SilentlyContinue
        return @{ code = $process.ExitCode; stdout = $outText; stderr = $errText }
    }

    function Get-VmState {
        $state = Invoke-Bvmenv @('state', $script:Vm, '--json', '--no-ocr') 120
        if ($state.code -eq 124 -or [string]::IsNullOrWhiteSpace($state.stdout)) { return $null }
        try { return ($state.stdout | ConvertFrom-Json) } catch { return $null }
    }

    function Get-VmPower {
        $state = Get-VmState
        if ($state -and $state.power) { return [string]$state.power }
        return 'unresponsive'
    }

    function Test-GuestAlive {
        $probe = Invoke-Bvmenv @('exec', $script:Vm, '--elevated', '--timeout', '30', '--',
            'cmd /c echo KDU-ALIVE') 60
        return ($probe.code -eq 0 -and (($probe.stdout + $probe.stderr) -match 'KDU-ALIVE'))
    }

    function Reset-Vm {
        Log "resetting $script:Vm to the clean snapshot"
        $reset = Invoke-Bvmenv @('reset', $script:Vm) 300
        Log "reset exit=$($reset.code)"
        if ($reset.code -ne 0) { throw "bvmenv reset failed: $($reset.stderr)" }
        $start = Invoke-Bvmenv @('start', $script:Vm) 240
        Log "start exit=$($start.code)"
        $ready = Invoke-Bvmenv @('wait-ready', $script:Vm, '--timeout', '600') 660
        Log "wait-ready exit=$($ready.code)"
        Push-PrepAssets
        if (-not $NoPrepare) { Invoke-GuestPrepare }
        Push-LabBundle
    }

    function Ensure-VmRunning {
        $power = Get-VmPower
        if ($power -ne 'on') {
            Log "vm power=$power; starting $script:Vm"
            $start = Invoke-Bvmenv @('start', $script:Vm) 240
            if ($start.code -ne 0) { throw "bvmenv start failed: $($start.stderr)" }
            $ready = Invoke-Bvmenv @('wait-ready', $script:Vm, '--timeout', '600') 660
            if ($ready.code -ne 0) { Log "wait-ready returned $($ready.code): $($ready.stderr)" }
        }
        if (-not (Test-GuestAlive)) {
            if ($NoReset) { throw 'guest is not answering and -NoReset was given' }
            Log 'guest is not answering; resetting the lab VM'
            Reset-Vm
        }
        Log "vm $script:Vm is running and answering"
    }

    function Get-ExploitInfo {
        if (-not (Test-Path $script:KduExe)) { throw "kdu.exe missing: $($script:KduExe) (build first)" }
        $previous = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try { $json = & $script:KduExe --json exploits list 2>&1 | Out-String } finally {
            $ErrorActionPreference = $previous
        }
        $items = @()
        try { $items = $json | ConvertFrom-Json } catch { throw "cannot parse kdu exploits list: $json" }
        return $items
    }

    function Get-DriverBlob([string] $Id, [string] $DriverFile) {
        $dataDir = Join-Path $Root "src/exploits/$Id/data"
        if (-not (Test-Path $dataDir)) { return $null }
        $blobs = @(Get-ChildItem $dataDir -File | Where-Object { $_.Extension -ne '.rc' })
        if ($blobs.Count -eq 0) { return $null }
        if ($blobs.Count -eq 1) { return $blobs[0] }
        # Prefer the blob whose name matches info.driver_file (or its stem),
        # otherwise refuse to guess: a wrong blob would sign/load the wrong image.
        $driverBase = [IO.Path]::GetFileNameWithoutExtension($DriverFile)
        $matches = @($blobs | Where-Object {
            $_.Name -ieq $DriverFile -or $_.Name -ieq ($DriverFile + '.bin') -or
            $_.BaseName -ieq $driverBase -or
            ([IO.Path]::GetFileNameWithoutExtension($_.Name) -ieq $driverBase)
        })
        if ($matches.Count -eq 1) { return $matches[0] }
        Log ("sign: ambiguous driver blob for {0} ({1}): {2}" -f $Id, $DriverFile,
             (($blobs | ForEach-Object { $_.Name }) -join ', '))
        return $null
    }

    function Get-SignatureInfo([string] $Path) {
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $subject = ''
            if ($signature.SignerCertificate) { $subject = [string]$signature.SignerCertificate.Subject }
            return @{ status = [string]$signature.Status; signer = $subject
                      leaf = $signature.SignerCertificate }
        } catch {
            return @{ status = 'error'; signer = ''; leaf = $null }
        }
    }

    function Sign-Drivers($Exploits) {
        New-Item -ItemType Directory -Force $script:SignedDir | Out-Null
        New-Item -ItemType Directory -Force $script:CertDir | Out-Null
        $signScript = Join-Path $Root 'scripts/sign.ps1'
        $cachePath = Join-Path $script:SignedDir 'sign-cache.json'
        $cache = @{}
        if (Test-Path $cachePath) {
            try {
                $document = Get-Content -LiteralPath $cachePath -Raw | ConvertFrom-Json
                foreach ($entry in $document.entries) { $cache[$entry.id] = $entry }
            } catch { Log "sign: ignoring unreadable cache ($cachePath)" }
        }
        $toSign = New-Object System.Collections.Generic.List[string]
        $sources = @{}
        foreach ($exploit in $Exploits) {
            $blob = Get-DriverBlob $exploit.id $exploit.driver_file
            if (-not $blob) { Log "sign: no driver blob for $($exploit.id)"; continue }
            $target = Join-Path $script:SignedDir $exploit.driver_file
            $sourceHash = (Get-FileHash -LiteralPath $blob.FullName -Algorithm SHA256).Hash.ToLower()
            $sources[$exploit.id] = @{ blob = $blob; source_hash = $sourceHash; target = $target }
            $cached = $cache[$exploit.id]
            $cachedValid = $false
            if ((-not $ForceSign) -and (Test-Path $target) -and $cached -and
                $cached.source_sha256 -eq $sourceHash) {
                $targetHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
                if ($targetHash -eq $cached.output_sha256) {
                    $signature = Get-SignatureInfo $target
                    $cachedValid = ($signature.status -eq 'Valid')
                }
            }
            if (-not $cachedValid) {
                Copy-Item -LiteralPath $blob.FullName -Destination $target -Force
                $toSign.Add($target)
            }
        }
        $leafTarget = Join-Path $script:CertDir 'xinda-leaf.cer'
        if ($toSign.Count -gt 0) {
            Log "signing $($toSign.Count) driver(s) with the XINDA test certificate"
            try {
                # In-process: `pwsh -File sign.ps1 -Files <array>` mis-binds a
                # multi-element array to separate positional args and fails.
                & $signScript -Files $toSign.ToArray() -ExportLeafCert $leafTarget | Out-Null
            } catch {
                throw ("signing failed: " + $_.Exception.Message)
            }
            Log 'signing step completed'
        } else {
            Log 'all drivers already signed (cache hit)'
        }
        # Verify every selected driver, then refresh the hash cache. Any invalid
        # signature is fatal: the matrix would be meaningless without it.
        $entries = New-Object System.Collections.Generic.List[object]
        foreach ($exploit in $Exploits) {
            if (-not $sources.ContainsKey($exploit.id)) { continue }
            $target = $sources[$exploit.id].target
            if (-not (Test-Path $target)) { throw "signed driver missing for $($exploit.id): $target" }
            $signature = Get-SignatureInfo $target
            if ($signature.status -ne 'Valid') {
                throw ("signed driver {0} has signature status {1}" -f $target, $signature.status)
            }
            if ($signature.signer -and $signature.signer -notmatch 'XINDA') {
                Log ("sign: warning: {0} signer is not XINDA: {1}" -f $exploit.id, $signature.signer)
            }
            $entries.Add([ordered]@{
                id = $exploit.id
                driver_file = $exploit.driver_file
                source = $sources[$exploit.id].blob.FullName
                source_sha256 = $sources[$exploit.id].source_hash
                output = $target
                output_sha256 = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLower()
                signer = $signature.signer
                signed_at = (Get-Date).ToString('o')
            })
        }
        if (-not (Test-Path $leafTarget)) {
            $sample = Get-ChildItem $script:SignedDir -Filter *.sys -File | Select-Object -First 1
            if ($sample) {
                $signature = Get-SignatureInfo $sample.FullName
                if ($signature.leaf) {
                    [IO.File]::WriteAllBytes($leafTarget, $signature.leaf.Export('Cert'))
                    Log "exported XINDA leaf from $($sample.Name)"
                }
            }
        }
        [ordered]@{ schema = 'blook-kdu.vmlab.signcache.v1'
                    entries = $entries } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $cachePath -Encoding utf8
        return $entries
    }

    function Push-ViaBvmenv {
        param([string] $Local, [string] $Guest, [int] $Timeout = 300)
        $result = Invoke-Bvmenv @('push', $script:Vm, $Local, $Guest) $Timeout
        if ($result.code -ne 0) {
            throw ("bvmenv push failed ({0} -> {1}): {2}{3}" -f $Local, $Guest,
                   $result.stdout, $result.stderr)
        }
        return $result
    }

    function New-RunTestScript {
        $lines = @('@echo off', 'set BLOOK_KDU_DRIVER_DIR=C:\byovd\drivers')
        if ($script:UnsafePhysical) { $lines += 'set BLOOK_KDU_ALLOW_UNSAFE_PHYSICAL=1' }
        $lines += @('C:\byovd\kdu.exe exploits test %1', 'exit /b %ERRORLEVEL%')
        $runnerHost = Join-Path $script:Out 'run-test.cmd'
        Set-Content -LiteralPath $runnerHost -Value $lines -Encoding ascii
        return $runnerHost
    }

    function Push-PrepAssets {
        # Certificates + preparation script only: Defender exclusions must exist
        # before the vulnerable driver images land in C:\byovd.
        New-Item -ItemType Directory -Force $script:CertDir | Out-Null
        Copy-Item (Join-Path $Root 'signer/tsa/tsa-root.cer') $script:CertDir -Force
        Copy-Item (Join-Path $Root 'signer/certs/verisign-cscs-2010.cer') $script:CertDir -Force
        Copy-Item (Join-Path $Root 'signer/certs/verisign-g5-mcvr.cer') $script:CertDir -Force
        if (-not (Test-Path (Join-Path $script:CertDir 'xinda-leaf.cer'))) {
            $sample = Get-ChildItem $script:SignedDir -Filter *.sys -File | Select-Object -First 1
            if ($sample) {
                $signature = Get-SignatureInfo $sample.FullName
                if ($signature.leaf) {
                    [IO.File]::WriteAllBytes((Join-Path $script:CertDir 'xinda-leaf.cer'),
                                             $signature.leaf.Export('Cert'))
                }
            }
        }
        Push-ViaBvmenv $script:CertDir 'C:\byovd\certs' 120 | Out-Null
        Push-ViaBvmenv (Join-Path $Root 'tools/vm-lab/guest-prepare.ps1') `
            'C:\byovd\guest-prepare.ps1' 120 | Out-Null
        Log 'pushed prepare assets (certs + guest-prepare.ps1)'
    }

    function Push-LabBundle {
        Push-ViaBvmenv $script:KduExe 'C:\byovd\kdu.exe' 180 | Out-Null
        Log 'pushed kdu.exe'
        Push-ViaBvmenv $script:SignedDir 'C:\byovd\drivers' 300 | Out-Null
        $driverCount = @(Get-ChildItem $script:SignedDir -Filter *.sys -File).Count
        Log "pushed signed drivers ($driverCount files)"
        $runner = New-RunTestScript
        Push-ViaBvmenv $runner 'C:\byovd\run-test.cmd' 120 | Out-Null
        Log ('pushed run-test.cmd' + $(if ($script:UnsafePhysical) { ' (unsafe-physical enabled)' } else { '' }))
    }

    function Invoke-GuestPrepare {
        $arguments = @('exec', $script:Vm, '--elevated', '--timeout', '180', '--',
            'powershell -NoProfile -ExecutionPolicy Bypass -File C:\byovd\guest-prepare.ps1 -ByovdDir C:\byovd')
        if ($script:TestSigning) { $arguments[-1] += ' -TestSigning' }
        $prep = Invoke-Bvmenv $arguments 240
        $header = "----- prepare {0} (exit={1}) -----" -f (Get-Date).ToString('o'), $prep.code
        Add-Content -LiteralPath (Join-Path $script:Out 'prepare.log') -Value $header -Encoding utf8
        Add-Content -LiteralPath (Join-Path $script:Out 'prepare.log') -Value $prep.stdout -Encoding utf8
        Add-Content -LiteralPath (Join-Path $script:Out 'prepare.log') -Value $prep.stderr -Encoding utf8
        $text = [string]$prep.stdout + [string]$prep.stderr
        $failed = ($text -match 'PREP status=fail')
        $rebootRequired = ($text -match 'PREP reboot_required=1')
        Log ("guest prepare: exit={0} status={1} reboot_required={2}" -f
            $prep.code, $(if ($failed) { 'fail' } else { 'ok/warn' }), $rebootRequired)
        if ($failed) { throw 'guest preparation failed (see prepare.log)' }
        if ($rebootRequired) {
            Log 'rebooting guest so testsigning / blocklist settings take effect'
            $reboot = Invoke-Bvmenv @('exec', $script:Vm, '--elevated', '--timeout', '60', '--',
                'cmd /c "shutdown /r /t 0 /f"') 90
            Log "guest reboot requested: $($reboot.code)"
            Start-Sleep -Seconds 15
            $ready = Invoke-Bvmenv @('wait-ready', $script:Vm, '--timeout', '600') 660
            if ($ready.code -ne 0) { throw 'guest did not come back after the lab-config reboot' }
            Log 'guest is ready after the lab-config reboot; re-running prepare'
            $again = Invoke-Bvmenv $arguments 240
            Add-Content -LiteralPath (Join-Path $script:Out 'prepare.log') -Value $again.stdout -Encoding utf8
            if (([string]$again.stdout + [string]$again.stderr) -match 'PREP status=fail') {
                throw 'guest preparation failed after the lab-config reboot (see prepare.log)'
            }
        }
    }

    function Get-ExecResult([string] $Id) {
        $command = "C:\byovd\run-test.cmd $Id"
        $exec = Invoke-Bvmenv @('exec', $script:Vm, '--elevated', '--timeout',
            [string]$TimeoutSeconds, '--', $command) ($TimeoutSeconds + 60)
        $stdout = [string]$exec.stdout
        $stderr = [string]$exec.stderr
        $output = (($stdout + "`n" + $stderr)).Trim()
        # bvmenv prints an "exit_code : N" header on stdout; keep it in raw logs
        # but parse only kdu output lines. Use Int64: exception exits can be
        # reported either signed (-1073741819) or unsigned (3221225477).
        $guestExit = $null
        if ($stdout -match 'exit_code\s*:\s*(-?\d+)') { $guestExit = [int64]$Matches[1] }
        return @{ code = $exec.code; stdout = $stdout; stderr = $stderr; output = $output
                  guest_exit = $guestExit; command = $command }
    }

    function Classify-Failure([string] $Output) {
        # Actionable buckets, most specific first. The likely cause is reported
        # in matrix.md so implementers know whose module to look at.
        if ($Output -match '0x800B010C|CERT_E_REVOKED|2148204812') {
            return @{ class = 'blocked-revoked'; host_blocked = $true
                      cause = 'signature revoked (CERT_E_REVOKED); lab signing/trust or test-signing not effective' }
        }
        if ($Output -match '(?i)0xE1\b|ERROR_VIRUS_INFECTED') {
            return @{ class = 'blocked-defender'; host_blocked = $true
                      cause = 'Defender (0xE1); guest Defender realtime/exclusion not effective' }
        }
        if ($Output -match '0x800B0109|CERT_E_UNTRUSTEDROOT') {
            return @{ class = 'blocked-untrusted-root'; host_blocked = $true
                      cause = 'untrusted root; guest trust store incomplete' }
        }
        if ($Output -match '0x800B0101|CERT_E_EXPIRED') {
            return @{ class = 'blocked-expired'; host_blocked = $true
                      cause = 'signer certificate expired (timestamp chain not trusted?)' }
        }
        if ($Output -match '0x800B010A|CERT_E_CHAINING') {
            return @{ class = 'blocked-chain'; host_blocked = $true
                      cause = 'cannot build a certificate chain; missing CA store entry' }
        }
        if ($Output -match '(?i)0x8007001F|(?<![0-9a-fA-F])0x1F\b') {
            return @{ class = 'driver-start-failed'; host_blocked = $false
                      cause = 'DriverEntry/init failed (0x1F / ERROR_GEN_FAILURE): hardware-dependent or unsupported build, not signature' }
        }
        if ($Output -match '(?i)StartService failed') {
            return @{ class = 'driver-start-failed'; host_blocked = $false
                      cause = 'driver failed to start (StartService); inspect the raw error code' }
        }
        if ($Output -match '(?i)cannot open device') {
            return @{ class = 'device-open-failed'; host_blocked = $false
                      cause = 'driver loaded but its device/IOCTL path did not open; ioctl/device-name bug' }
        }
        if ($Output -match '(?i)cannot create service') {
            return @{ class = 'service-create-failed'; host_blocked = $false
                      cause = 'SCM refused the service; stale service or path problem' }
        }
        if ($Output -match '(?i)not.?supported|unsupported|not_supported') {
            return @{ class = 'unsupported'; host_blocked = $false
                      cause = 'exploit/backend reports unsupported on this build' }
        }
        if ($Output -match '(?i)module enumeration failed|cannot read|read_virtual|translate|page.?table|physical') {
            return @{ class = 'primitive-failed'; host_blocked = $false
                      cause = 'driver loaded but the kernel memory primitive failed (ioctl/translation)' }
        }
        return @{ class = 'fail-other'; host_blocked = $false; cause = 'unclassified failure; see raw log' }
    }

    function Get-CrashInfo($State) {
        $crash = [ordered]@{ crash = $false; reason = ''; stop_code = ''; screen = ''
                             power = 'unknown'; screenshot = '' }
        if (-not $State) {
            $crash.crash = $true; $crash.reason = 'bvmenv state unavailable (guest unresponsive/hung)'
            return $crash
        }
        $crash.power = [string]$State.power
        if ($State.screen) {
            $crash.screen = [string]$State.screen.classification
            $crash.stop_code = [string]$State.screen.stop_code
            $crash.screenshot = [string]$State.screen.screenshot
        }
        if ($State.power -ne 'on') {
            $crash.crash = $true; $crash.reason = "power=$($State.power)"
            return $crash
        }
        if ($crash.screen -eq 'bsod') {
            $crash.crash = $true; $crash.reason = 'bugcheck screen (bsod)'
            return $crash
        }
        if ($crash.screen -in @('black', 'hang')) {
            if ($State.guest_queryable -eq $false -or -not (Test-GuestAlive)) {
                $crash.crash = $true; $crash.reason = "screen=$($crash.screen) and guest is not answering"
                return $crash
            }
        }
        return $crash
    }

    function Invoke-SingleTest([string] $Id) {
        $exec = Get-ExecResult $Id
        $state = Get-VmState
        $crash = Get-CrashInfo $state
        $result = [ordered]@{
            status = 'FAIL'; classification = ''; likely_cause = ''
            backend = ''; ntoskrnl = ''; detail = ''
            exec = $exec; crash = $crash; retried = $false
        }
        if ($exec.output -match 'PASS\s+([\w-]+).*?ntoskrnl=(0x[0-9a-fA-F]+).*?backend=([\w-]+)') {
            $result.status = 'PASS'
            $result.ntoskrnl = $Matches[2]
            $result.backend = $Matches[3]
            $result.detail = "ntoskrnl=$($Matches[2]) backend=$($Matches[3])"
        } elseif ($exec.output -match '(?m)^\s*SKIP\s+([\w-]+)\s+(.*)$') {
            # kdu prints SKIP for kill-only drivers (no kernel memory primitive):
            # a documented non-failure, not a matrix FAIL.
            $result.status = 'SKIP'
            $result.classification = 'skipped-no-primitive'
            $result.likely_cause = 'kill-only driver: no kernel memory primitive, the memory self-test does not apply'
            $result.detail = (([string]$Matches[2]).Trim() -replace '\s+', ' ')
        } else {
            $failLine = ($exec.output -split "`n" | Where-Object { $_ -match '^\s*FAIL' } |
                         Select-Object -First 1)
            if ($failLine) {
                $result.detail = ($failLine.Trim() -replace '\s+', ' ')
                $bucket = Classify-Failure $exec.output
                $result.classification = $bucket.class
                $result.likely_cause = $bucket.cause
            } elseif ($null -ne $exec.guest_exit -and
                      ($exec.guest_exit -lt 0 -or $exec.guest_exit -ge 3221225477)) {
                # kdu.exe itself died in user mode (e.g. 0xC0000005): not a
                # driver-load failure, an exploit/ioctl bug in the CLI.
                $result.classification = 'kdu-crashed'
                $exitU32 = if ($exec.guest_exit -lt 0) {
                    [uint32]([int64]$exec.guest_exit + 4294967296)
                } else { [uint32]$exec.guest_exit }
                $result.likely_cause = ('kdu.exe terminated with exception 0x{0:x8}; exploit ioctl path crashed user mode' -f $exitU32)
                $result.detail = ('guest exit 0x{0:x8}' -f $exitU32)
            } elseif ($exec.code -eq 124) {
                $result.status = 'TIMEOUT'
                $result.classification = 'timeout'
                $result.likely_cause = "no answer within ${TimeoutSeconds}s (driver hang or very slow primitive)"
                $result.detail = [string]$exec.stderr
            } elseif ([string]::IsNullOrWhiteSpace($exec.output)) {
                $result.status = 'TIMEOUT'
                $result.classification = 'timeout-empty-output'
                $result.likely_cause = 'bvmenv exec returned nothing (guest wedged)'
                $result.detail = 'empty guest output'
            } else {
                $result.classification = 'unparsed'
                $result.likely_cause = 'no PASS/FAIL line in the guest output'
                $result.detail = (($exec.output -split "`n" | Select-Object -First 3) -join ' / ')
            }
        }
        if ($crash.crash) {
            $result.status = 'CRASH'
            $result.classification = 'bugcheck'
            $result.likely_cause = "guest crashed/hung: $($crash.reason)" + $(if ($crash.stop_code) { " stop_code=$($crash.stop_code)" } else { '' })
        }
        return $result
    }

    function Test-TransientFailure($Result) {
        if ($Result.status -eq 'CRASH') { return $false }
        $text = [string]$Result.detail
        if ($text -match '0x430\b|0x00000430|ERROR_SERVICE_MARKED_FOR_DELETE') { return $true }
        if ($Result.classification -eq 'device-open-failed' -and $text -match 'did not appear') { return $true }
        return $false
    }

    function Clear-StaleService([string] $Service) {
        if ([string]::IsNullOrWhiteSpace($Service)) { return }
        $command = 'cmd /c "sc stop {0} 2>nul & sc delete {0} 2>nul & echo service-cleanup"' -f $Service
        try {
            Invoke-Bvmenv @('exec', $script:Vm, '--elevated', '--timeout', '30', '--', $command) 60 | Out-Null
        } catch { }
    }

    # -----------------------------------------------------------------------
    # inputs
    # -----------------------------------------------------------------------
    # `kdu --json exploits list` names the driver field "driver" (the DriverFile
    # field of ExploitInfo); normalize it so the rest of the script has one name.
    $exploits = @(Get-ExploitInfo | ForEach-Object {
        $driverFile = if ($_.driver_file) { [string]$_.driver_file }
                      elseif ($_.driver) { [string]$_.driver }
                      else { '' }
        [pscustomobject]@{
            id = [string]$_.id
            driver_file = $driverFile
            service = [string]$_.service
            raw = $_
        }
    })
    if ($exploits.Count -gt 0 -and -not $exploits[0].driver_file) {
        throw 'kdu exploited list has no driver field (expected "driver")'
    }
    if ($All) { $Ids = @($exploits | ForEach-Object { $_.id }) }
    if ($RetryFailed) {
        # Re-run only the ids that failed in an existing matrix (same -Out, or
        # -Result <path>). The previous matrix is merged below, so PASS rows
        # survive and only the retried rows are refreshed.
        $retrySource = if ($MergeResult) { $MergeResult }
                       elseif (Test-Path (Join-Path $Out 'matrix.json')) { Join-Path $Out 'matrix.json' }
                       else { '' }
        if (-not $retrySource) {
            throw '-RetryFailed needs an existing <Out>/matrix.json or -Result <path>'
        }
        $previousRows = @(Get-Content -LiteralPath $retrySource -Raw | ConvertFrom-Json)
        $failedIds = @($previousRows |
            Where-Object { $_.status -in @('FAIL', 'TIMEOUT', 'CRASH', 'ERROR') -or
                           [string]::IsNullOrWhiteSpace([string]$_.status) } |
            ForEach-Object { [string]$_.id })
        if ($Ids.Count -gt 0) {
            $failedIds = @($failedIds | Where-Object { $Ids -contains $_ })
        }
        $selected = @($exploits | Where-Object { $failedIds -contains $_.id })
        $unknown = @($failedIds | Where-Object { $exploits.id -notcontains $_ })
        if ($unknown.Count -gt 0) {
            Log "retry: ids no longer compiled (skipped): $($unknown -join ', ')"
        }
        if ($selected.Count -eq 0) { throw 'nothing to retry' }
        Log "retry mode: $($selected.Count) previously-failed id(s) from $retrySource"
    } else {
        $selected = @($exploits | Where-Object { $Ids -contains $_.id })
        $missing = @($Ids | Where-Object { $selected.id -notcontains $_ })
        if ($missing.Count -gt 0) { Log "unknown exploit ids (skipped): $($missing -join ', ')" }
        if ($selected.Count -eq 0) { throw 'no matching exploits' }
    }
    Log "kdu.exe reports $($exploits.Count) exploit(s); selected $($selected.Count)"

    $buildInfo = [ordered]@{
        kdu_sha256 = (Get-FileHash -LiteralPath $script:KduExe -Algorithm SHA256).Hash.ToLower()
        kdu_version = (Get-Content (Join-Path $Root 'version.txt') -Raw).Trim()
        bvmenv_sha256 = (Get-FileHash -LiteralPath $script:Bvmenv -Algorithm SHA256).Hash.ToLower()
        bvmenv_version = ''
    }
    try { $buildInfo.bvmenv_version = ((& $script:Bvmenv version) | Out-String).Trim() } catch { }
    $guestBuild = ''

    Ensure-VmRunning
    $signedEntries = @()
    if (-not $NoSign) {
        $signedEntries = Sign-Drivers $selected
    } else {
        Log 'signing skipped (-NoSign)'
    }
    if (-not $NoPush) { Push-PrepAssets }
    if (-not $NoPrepare) { Invoke-GuestPrepare }
    $prepLog = Join-Path $Out 'prepare.log'
    if (Test-Path $prepLog) {
        $prepText = Get-Content -LiteralPath $prepLog -Raw
        if ($prepText -match 'PREP info guest os=(\S+) build=(\S+)') {
            $guestBuild = "{0} build {1}" -f $Matches[1], $Matches[2]
        }
    }
    if (-not $NoPush) { Push-LabBundle }

    # -----------------------------------------------------------------------
    # matrix
    # -----------------------------------------------------------------------
    $resultPath = Join-Path $Out 'matrix.json'
    $mergePath = if ($MergeResult) { $MergeResult } elseif (Test-Path $resultPath) { $resultPath } else { '' }
    $matrix = [ordered]@{}
    if ($mergePath -and (Test-Path $mergePath)) {
        try {
            $previous = @(Get-Content -LiteralPath $mergePath -Raw | ConvertFrom-Json)
            foreach ($row in $previous) { if ($row.id) { $matrix[$row.id] = $row } }
            Log "merged $($matrix.Count) previous result(s) from $mergePath"
        } catch { Log "could not merge previous results from $($mergePath): $_" }
    }
    $crashes = New-Object System.Collections.Generic.List[object]
    $stopRequested = $false

    $index = 0
    foreach ($exploit in $selected) {
        $index++
        $id = $exploit.id
        if ($stopRequested) {
            $matrix[$id] = [pscustomobject]@{
                id = $id; status = 'SKIP'; classification = 'skipped'
                detail = 'skipped after a crash with -NoReset'; driver_file = $exploit.driver_file
                raw = ''; at = (Get-Date).ToString('o')
            }
            continue
        }
        $rawPath = Join-Path $Out ("raw/{0}.log" -f $id)
        Log ("[{0}/{1}] test {2} ({3})" -f $index, $selected.Count, $id, $exploit.driver_file)
        $started = Get-Date
        $testResult = Invoke-SingleTest $id
        if ($null -eq $testResult -or -not ($testResult -is [System.Collections.IDictionary]) -or
            [string]::IsNullOrWhiteSpace([string]$testResult.status)) {
            # Defensive: never write an empty matrix row. This should not happen,
            # but a malformed function result must be visible, not silent.
            Log ("harness warning: Invoke-SingleTest returned no usable result for {0}" -f $id)
            $testResult = [ordered]@{
                status = 'ERROR'; classification = 'harness-error'
                likely_cause = 'Invoke-SingleTest returned no usable result'
                backend = ''; ntoskrnl = ''; detail = 'harness error'
                exec = @{ code = $null; stdout = ''; stderr = ''; output = ''
                          guest_exit = $null; command = ('C:\byovd\run-test.cmd ' + $id) }
                crash = [ordered]@{ crash = $false; reason = ''; stop_code = ''
                                    screen = ''; power = 'unknown'; screenshot = '' }
                retried = $false
            }
        }
        if ($testResult.status -ne 'CRASH' -and (Test-TransientFailure $testResult)) {
            Log ("  -> transient failure ({0}): {1}" -f $testResult.classification, $testResult.detail)
            Log ("     cleaning service '{0}' and retrying the id once" -f $exploit.service)
            # ERROR_SERVICE_MARKED_FOR_DELETE (0x430) needs the SCM delete to
            # complete; give it a longer window than a single 3 s nap.
            Start-Sleep -Seconds 8
            Clear-StaleService $exploit.service
            Start-Sleep -Seconds 8
            $testResult = Invoke-SingleTest $id
            $testResult.retried = $true
            Log ("  -> retry: {0} [{1}] {2}" -f $testResult.status, $testResult.classification, $testResult.detail)
        }
        $exec = $testResult.exec
        $crash = $testResult.crash
        $status = $testResult.status
        $classification = $testResult.classification
        $likelyCause = $testResult.likely_cause
        $backend = $testResult.backend
        $ntoskrnl = $testResult.ntoskrnl
        $detail = $testResult.detail
        if ($crash.crash) {
            $crashes.Add([pscustomobject]@{
                id = $id; at = (Get-Date).ToString('o'); reason = $crash.reason
                stop_code = $crash.stop_code; screen = $crash.screen; power = $crash.power
                screenshot = $crash.screenshot; recovered = $false
            })
        }
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add("# vm-lab raw: $id")
        $lines.Add("# at: $($started.ToString('o'))")
        $lines.Add("# command: $($exec.command)")
        $lines.Add("# bvmenv exit: $($exec.code) guest exit: $($exec.guest_exit)")
        $lines.Add("# status: $status classification: $classification")
        $lines.Add("# vm: power=$($crash.power) screen=$($crash.screen) stop_code=$($crash.stop_code)")
        $lines.Add('')
        $lines.AddRange([string[]]($exec.stdout -split "`r?`n"))
        if ($exec.stderr) {
            $lines.Add('')
            $lines.Add('--- stderr ---')
            $lines.AddRange([string[]]($exec.stderr -split "`r?`n"))
        }
        Set-Content -LiteralPath $rawPath -Value $lines -Encoding utf8
        $durationMs = [int]((Get-Date) - $started).TotalMilliseconds
        $row = [pscustomobject]@{
            id = $id; status = $status; classification = $classification
            likely_cause = $likelyCause
            host_blocked = [bool]($classification -in
                @('blocked-revoked', 'blocked-defender', 'blocked-untrusted-root', 'blocked-expired', 'blocked-chain'))
            backend = $backend; ntoskrnl = $ntoskrnl; driver_file = $exploit.driver_file
            exit = $exec.code; guest_exit = $exec.guest_exit; duration_ms = $durationMs
            detail = $detail; raw = $rawPath; at = (Get-Date).ToString('o')
            crash_stop_code = $crash.stop_code; retried = [bool]$testResult.retried
        }
        $matrix[$id] = $row
        $mark = switch ($status) { 'PASS' { 'PASS' } 'CRASH' { 'CRASH' } 'SKIP' { 'SKIP' } default { 'FAIL' } }
        Log ("  -> {0} [{1}] {2} {3}" -f $mark, $classification, $detail,
            $(if ($durationMs -gt 0) { "(${durationMs}ms)" } else { '' }))
        if ($status -eq 'CRASH') {
            if ($NoReset) {
                Log 'crash detected with -NoReset: aborting the remaining ids'
                $stopRequested = $true
            } else {
                Log 'recovering the VM after the crash'
                Reset-Vm
                if ($crashes.Count -gt 0) { $crashes[$crashes.Count - 1].recovered = $true }
            }
        }
        if (($index % $BatchLogEvery) -eq 0) {
            $matrix.Values | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding utf8
            Log "checkpoint: matrix.json written after $index id(s)"
        }
    }

    # -----------------------------------------------------------------------
    # outputs
    # -----------------------------------------------------------------------
    $rows = @($matrix.Values | Sort-Object id)
    $rows | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding utf8
    $statusCounts = [ordered]@{}
    foreach ($status in @('PASS', 'FAIL', 'CRASH', 'TIMEOUT', 'SKIP')) {
        $statusCounts[$status] = @($rows | Where-Object { $_.status -eq $status }).Count
    }
    $classCounts = [ordered]@{}
    foreach ($row in $rows) {
        $key = if ($row.classification) { [string]$row.classification } else { 'pass' }
        if (-not $classCounts.Contains($key)) { $classCounts[$key] = 0 }
        $classCounts[$key]++
    }
    $summary = [ordered]@{
        schema = 'blook-kdu.vmlab.matrix.v1'
        vm = $script:Vm
        guest_build = $guestBuild
        testsigning = [bool]$TestSigning
        unsafe_physical = [bool]$UnsafePhysical
        timeout_seconds = $TimeoutSeconds
        generated = (Get-Date).ToString('o')
        build = $buildInfo
        totals = [ordered]@{ total = $rows.Count } + $statusCounts
        by_classification = $classCounts
        crashes = $crashes
        signed_drivers = $signedEntries
        rows = $rows
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Out 'summary.json') -Encoding utf8

    $markdown = New-Object System.Collections.Generic.List[string]
    $markdown.Add("# blook-kdu VM exploit matrix")
    $markdown.Add('')
    $markdown.Add(("- vm: {0}   guest: {1}   testsigning: {2}   unsafe-physical: {3}" -f
                   $script:Vm, $(if ($guestBuild) { $guestBuild } else { 'unknown' }),
                   $TestSigning, $UnsafePhysical))
    $markdown.Add(("- kdu.exe sha256: {0}   timeout/id: {1}s   generated: {2}" -f
                   $buildInfo.kdu_sha256, $TimeoutSeconds, (Get-Date).ToString('o')))
    $markdown.Add('')
    $markdown.Add(("**{0} exploit(s): {1} PASS, {2} FAIL, {3} CRASH, {4} TIMEOUT, {5} SKIP**" -f
                   $rows.Count, $statusCounts['PASS'], $statusCounts['FAIL'],
                   $statusCounts['CRASH'], $statusCounts['TIMEOUT'], $statusCounts['SKIP']))
    $markdown.Add('')
    $markdown.Add('## Results')
    $markdown.Add('')
    $markdown.Add('| id | status | classification | backend | ntoskrnl | detail |')
    $markdown.Add('| --- | --- | --- | --- | --- | --- |')
    foreach ($row in $rows) {
        $markdown.Add(("| {0} | {1} | {2} | {3} | {4} | {5} |" -f
            $row.id, $row.status, $row.classification, $row.backend, $row.ntoskrnl,
            (([string]$row.detail) -replace '\|', '/')))
    }
    $failures = @($rows | Where-Object { $_.status -notin @('PASS', 'SKIP') })
    if ($failures.Count -gt 0) {
        $markdown.Add('')
        $markdown.Add('## Actionable failures')
        $markdown.Add('')
        $markdown.Add('| id | status | classification | likely cause | raw |')
        $markdown.Add('| --- | --- | --- | --- | --- |')
        foreach ($row in $failures) {
            $markdown.Add(("| {0} | {1} | {2} | {3} | {4} |" -f
                $row.id, $row.status, $row.classification,
                (([string]$row.likely_cause) -replace '\|', '/'), $row.raw))
        }
    }
    if ($crashes.Count -gt 0) {
        $markdown.Add('')
        $markdown.Add('## Crashes (VM bugchecks/hangs)')
        $markdown.Add('')
        foreach ($crash in $crashes) {
            $markdown.Add(("- **{0}**: {1}; stop_code={2}; screen={3}; recovered={4}" -f
                $crash.id, $crash.reason, $(if ($crash.stop_code) { $crash.stop_code } else { 'n/a' }),
                $crash.screen, $crash.recovered))
        }
    }
    $markdown.Add('')
    $markdown.Add('## How to consume this matrix')
    $markdown.Add('')
    $markdown.Add('- `matrix.json` rows: `id,status,classification,likely_cause,host_blocked,backend,ntoskrnl,driver_file,exit,guest_exit,duration_ms,detail,raw,at,crash_stop_code`.')
    $markdown.Add('- `status` is PASS/FAIL/CRASH/TIMEOUT/SKIP; `classification` buckets failures (blocked-revoked, driver-start-failed, primitive-failed, bugcheck, ...).')
    $markdown.Add('- `raw/<id>.log` keeps the exact guest command and the full stdout/stderr for that id.')
    $markdown | Set-Content -LiteralPath (Join-Path $Out 'matrix.md') -Encoding utf8
    Log ("matrix done: {0} rows, {1} PASS, {2} FAIL, {3} CRASH -> {4}" -f
        $rows.Count, $statusCounts['PASS'], $statusCounts['FAIL'], $statusCounts['CRASH'], $resultPath)
    if ($statusCounts['FAIL'] -gt 0 -or $statusCounts['CRASH'] -gt 0 -or
        $statusCounts['TIMEOUT'] -gt 0) {
        $script:ExitCode = 1
    }
}
finally {
    if ($owned) { [void]$mutex.ReleaseMutex() }
    $mutex.Dispose()
}
exit $script:ExitCode
