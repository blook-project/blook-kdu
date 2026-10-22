# blook-kdu VM lab: one-shot guest preparation (idempotent, elevated).
#
# Runs INSIDE the disposable bvmenv guest (pushed to C:\byovd\guest-prepare.ps1 by
# scripts/vm-lab.ps1). The guest is treated as hostile/disposable: nothing here
# ever touches the host, and every step is safe to repeat.
#
# What it does (and why):
#   1. Defender: realtime + IOAV scanning off where the guest allows it, and
#      C:\byovd + C:\Windows\Temp excluded, so the staged vulnerable drivers are
#      not quarantined. (Tamper protection can pin realtime scanning on; the
#      exclusion is what keeps the lab unblocked.)
#   2. Signature trust: the lab re-signs every bundled driver with the legacy
#      XINDA SPC test certificate (scripts/sign.ps1) because the vendor images
#      are revoked/blocklisted by current Microsoft policy. The guest must trust
#      the whole chain: Blook Local TSA root -> root, VeriSign code-signing CAs ->
#      CA, and the XINDA leaf -> trustedpublisher.
#   3. Lab-only kernel config (the disposable guest only):
#        - Microsoft Vulnerable Driver Blocklist off
#          (HKLM\SYSTEM\CurrentControlSet\Control\CI\Config\VulnerableDriverBlocklistEnable=0)
#        - test signing + no integrity checks when the caller asks for it
#        - CryptoAPI URL cache (revocation lists) cleared
#      These need a reboot; the script reports PREP reboot_required=1 and the host
#      runner performs the reboot and re-runs the script.
#   4. Optional: bcdedit /set nx AlwaysOff (off by default; only needed for
#      experiments that execute from kernel pool, not for `exploits test`).
#
# Output protocol parsed by scripts/vm-lab.ps1:
#   PREP ok   <step> <detail>
#   PREP fail <step> <detail>
#   PREP info guest os=<version> build=<build> host=<name>
#   PREP reboot_required=1
#   PREP status=ok|warn|fail
# `fail` for a trust step is fatal (status=fail, exit 1); Defender warnings keep
# status=warn but still exit 0 because the trust path is what gates driver load.
[CmdletBinding()]
param(
    [string] $ByovdDir = 'C:\byovd',
    [switch] $SetNxAlwaysOff,
    [switch] $TestSigning
)

$ErrorActionPreference = 'Continue'

function Write-Step {
    param([string] $Name, [bool] $Ok, [string] $Detail = '')
    $state = if ($Ok) { 'ok' } else { 'fail' }
    Write-Output ("PREP {0} {1} {2}" -f $state, $Name, $Detail.Trim())
}

$fatal = $false
$warn = $false
$rebootRequired = $false
$configChanged = $false

# ---------------------------------------------------------------------------
# 0. Environment facts (recorded in the host matrix).
# ---------------------------------------------------------------------------
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    Write-Output ("PREP info guest os={0} build={1} host={2}" -f $os.Version,
                  $os.BuildNumber, $env:COMPUTERNAME)
} catch {
    Write-Step 'guest-os' $false $_.Exception.Message
}
$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Step 'elevated' $elevated 'administrator token'
if (-not $elevated) { $fatal = $true }

# ---------------------------------------------------------------------------
# 1. Defender: realtime + IOAV off, lab directories excluded.
# ---------------------------------------------------------------------------
$defenderProblems = @()
try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
} catch {
    $defenderProblems += ('realtime: ' + $_.Exception.Message)
}
try {
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
} catch {
    $defenderProblems += ('ioav: ' + $_.Exception.Message)
}
# Best effort hardening; these can be locked down by tamper protection.
try { Set-MpPreference -DisableScriptScanning $true -ErrorAction Stop } catch { }
try { Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction Stop } catch { }
foreach ($path in @($ByovdDir, (Join-Path $env:SystemRoot 'Temp'))) {
    try {
        Add-MpPreference -ExclusionPath $path -ErrorAction Stop
    } catch {
        $defenderProblems += ("exclusion ${path}: " + $_.Exception.Message)
    }
}
# Verify what the guest actually reports. Get-MpPreference can be slow; keep the
# result in the log so a half-disabled Defender is visible in the matrix.
$preference = $null
try { $preference = Get-MpPreference -ErrorAction Stop } catch {
    $defenderProblems += ('Get-MpPreference: ' + $_.Exception.Message)
}
if ($preference) {
    if ($preference.DisableRealtimeMonitoring -ne $true) {
        $defenderProblems += 'realtime protection still enabled (tamper protection?)'
    }
    if ($preference.DisableIOAVProtection -ne $true) {
        $defenderProblems += 'IOAV protection still enabled (tamper protection?)'
    }
    $missing = @()
    foreach ($path in @($ByovdDir, (Join-Path $env:SystemRoot 'Temp'))) {
        if (@($preference.ExclusionPath) -notcontains $path) { $missing += $path }
    }
    if ($missing.Count -gt 0) {
        $defenderProblems += ('missing exclusions: ' + ($missing -join ','))
    }
}
if ($defenderProblems.Count -eq 0) {
    Write-Step 'defender' $true 'realtime+ioav off, C:\byovd and %TEMP% excluded'
} else {
    $warn = $true
    Write-Step 'defender' $false ($defenderProblems -join '; ')
}

# ---------------------------------------------------------------------------
# 2. Trust the re-signing chain (root <- TSA root; CA <- VeriSign; leaf -> publisher).
# ---------------------------------------------------------------------------
$certsDir = Join-Path $ByovdDir 'certs'
$stores = @(
    @{ store = 'root'; file = 'tsa-root.cer' },
    @{ store = 'CA'; file = 'verisign-cscs-2010.cer' },
    @{ store = 'CA'; file = 'verisign-g5-mcvr.cer' },
    @{ store = 'trustedpublisher'; file = 'xinda-leaf.cer' }
)
foreach ($item in $stores) {
    $file = Join-Path $certsDir $item.file
    $detail = ''
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Step ("trust/{0}/{1}" -f $item.store, $item.file) $false "missing $file"
        $fatal = $true
        continue
    }
    try {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($file)
        $thumbprint = $certificate.Thumbprint
        # certutil is the least surprising way to write LocalMachine stores from
        # an elevated (possibly SYSTEM) context, including idempotent overwrite.
        $output = & certutil.exe -addstore -f $item.store $file 2>&1
        $exit = $LASTEXITCODE
        $present = Test-Path -LiteralPath ("Cert:\LocalMachine\{0}\{1}" -f $item.store, $thumbprint)
        if ($exit -eq 0 -and $present) {
            Write-Step ("trust/{0}/{1}" -f $item.store, $item.file) $true "thumbprint=$thumbprint"
        } else {
            if (-not $present) { $detail = 'certificate not present in store after certutil' }
            else { $detail = "certutil exit $exit" }
            if ($output) { $detail += ('; ' + (($output | Out-String).Trim())) }
            Write-Step ("trust/{0}/{1}" -f $item.store, $item.file) $false $detail
            $fatal = $true
        }
    } catch {
        Write-Step ("trust/{0}/{1}" -f $item.store, $item.file) $false $_.Exception.Message
        $fatal = $true
    }
}

# ---------------------------------------------------------------------------
# 3. Lab-only kernel configuration (testsigning + vulnerable-driver blocklist).
# ---------------------------------------------------------------------------
function Get-CurrentBcd {
    $output = & bcdedit.exe /enum '{current}' 2>&1
    $text = ($output | Out-String)
    return @{
        testsigning = ($text -match '(?im)^\s*testsigning\s+Yes\s*$')
        nointegritychecks = ($text -match '(?im)^\s*nointegritychecks\s+Yes\s*$')
        text = $text
    }
}

# 3a. Vulnerable driver blocklist: a WDAC policy, independent of DSE. It blocks
# drivers even under test signing, so the disposable guest switches it off.
$blocklistKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
try {
    if (-not (Test-Path $blocklistKey)) { New-Item -Path $blocklistKey -Force | Out-Null }
    $previous = (Get-ItemProperty -Path $blocklistKey -Name VulnerableDriverBlocklistEnable -ErrorAction SilentlyContinue)
    $before = $null
    if ($previous) { $before = $previous.VulnerableDriverBlocklistEnable }
    Set-ItemProperty -Path $blocklistKey -Name VulnerableDriverBlocklistEnable -Type DWord -Value 0 -ErrorAction Stop
    $now = (Get-ItemProperty -Path $blocklistKey -Name VulnerableDriverBlocklistEnable).VulnerableDriverBlocklistEnable
    Write-Step 'lab/blocklist' ($now -eq 0) ("VulnerableDriverBlocklistEnable=0 (was " + $(if ($null -eq $before) { 'unset' } else { $before }) + ")")
    if ($before -ne 0) { $configChanged = $true }
} catch {
    Write-Step 'lab/blocklist' $false $_.Exception.Message
    $warn = $true
}
try {
    # Disable the reputation/HDCP CI policy layer too (best effort).
    $policyKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    if (Test-Path $policyKey) {
        Set-ItemProperty -Path $policyKey -Name VerifiedAndReputablePolicyState -Type DWord -Value 0 -ErrorAction SilentlyContinue
    }
} catch { }

# 3b. Clear CryptoAPI URL caches so a stale CRL cannot leak into the next test.
try { & certutil.exe -urlcache '*' delete 2>&1 | Out-Null } catch { }

# 3c. Test signing: required because the legacy XINDA chain is revoked.
if ($TestSigning) {
    $current = Get-CurrentBcd
    if ($current.testsigning -and $current.nointegritychecks) {
        Write-Step 'lab/testsigning' $true 'already testsigning+nointegritychecks'
    } else {
        $set = & cmd.exe /c 'bcdedit /set testsigning on && bcdedit /set nointegritychecks on' 2>&1
        $exit = $LASTEXITCODE
        $after = Get-CurrentBcd
        Write-Step 'lab/testsigning' ($exit -eq 0 -and $after.testsigning -and $after.nointegritychecks) `
            (($set | Out-String).Trim())
        if ($exit -ne 0) { $warn = $true }
        $configChanged = $true
    }
} else {
    Write-Step 'lab/testsigning' $true 'not requested'
}

# 3d. A reboot is needed when BCD or the blocklist policy changed. The marker is
# written by the post-reboot invocation, so a snapshot revert (which restores the
# old BCD and deletes C:\byovd) naturally asks for another reboot.
$marker = Join-Path $ByovdDir 'labconfig.applied'
if ($configChanged) {
    Remove-Item -LiteralPath $marker -Force -ErrorAction SilentlyContinue
    $rebootRequired = $true
} else {
    New-Item -ItemType Directory -Force -Path $ByovdDir | Out-Null
    Set-Content -LiteralPath $marker -Encoding ascii -Value (("applied_at={0}`r`ntestsigning={1}" -f
        (Get-Date).ToString('o'), $TestSigning))
}
Write-Output ("PREP reboot_required={0}" -f $(if ($rebootRequired) { 1 } else { 0 }))

# ---------------------------------------------------------------------------
# 4. Optional bcdedit (never change nx unless the caller asks for it).
# ---------------------------------------------------------------------------
if ($SetNxAlwaysOff) {
    $output = & bcdedit.exe /set nx AlwaysOff 2>&1
    $exit = $LASTEXITCODE
    Write-Step 'bcdedit/nx' ($exit -eq 0) (($output | Out-String).Trim())
    if ($exit -ne 0) { $warn = $true }
} else {
    Write-Step 'bcdedit/nx' $true 'unchanged (pass -SetNxAlwaysOff if a test needs executable pool)'
}

# ---------------------------------------------------------------------------
# 5. Lab directory + a marker proving the whole prep ran to completion.
# ---------------------------------------------------------------------------
foreach ($directory in @($ByovdDir, (Join-Path $ByovdDir 'drivers'),
                        (Join-Path $ByovdDir 'certs'))) {
    try {
        New-Item -ItemType Directory -Force -Path $directory -ErrorAction Stop | Out-Null
    } catch {
        Write-Step 'mkdir' $false $_.Exception.Message
        $fatal = $true
    }
}
if (-not $fatal -and -not $rebootRequired) {
    try {
        Set-Content -LiteralPath (Join-Path $ByovdDir 'prepare.ok') -Encoding ascii `
            -Value (("prepared_at={0}`r`nhost={1}" -f (Get-Date).ToString('o'), $env:COMPUTERNAME))
    } catch {
        Write-Step 'marker' $false $_.Exception.Message
    }
}

if ($fatal) {
    Write-Output 'PREP status=fail'
    exit 1
}
if ($warn) {
    Write-Output 'PREP status=warn'
    exit 0
}
Write-Output 'PREP status=ok'
exit 0
