# E2E guard: PortableTailscale must never require administrator privileges.
#
# Windows shows the "allow ... on private and public networks" firewall dialog
# the moment a process listens on a non-loopback socket, and a standard user
# cannot dismiss that dialog — only an administrator can. So this script
# proves, against the freshly built exe:
#
#   1. the exe does not request UAC elevation (no requireAdministrator or
#      highestAvailable anywhere in its bytes, which covers any embedded
#      manifest),
#   2. it starts and keeps running as a freshly created *standard* user,
#      from a directory that user can execute (the runner workspace is not
#      readable by arbitrary local users),
#   3. for the whole audit window it never owns a non-loopback TCP listener,
#      and never owns a non-loopback UDP socket that persists across three
#      consecutive samples (a fleeting UDP socket is an outbound client such
#      as a DNS query; those do not trigger the dialog, persistent ones do —
#      the failure fires immediately on the third strike, not at the end),
#   4. the audit observed the process actually networking (an established
#      outbound TCP connection is the Tailscale control/DERP path, so the
#      tsnet engine really started) and at least one of its sockets, so a
#      blind or wrong-process pass cannot fake success.
#
# Credentials for the throwaway local user are generated at random per run
# and never leave memory; cleanup failures fail the run too.
#
# Run by .github/workflows/windows-build.yml after the build step.

param(
    [Parameter(Mandatory = $true)] [string] $ExePath,
    [int] $Seconds = 30,
    [int] $SampleSeconds = 2
)

$ErrorActionPreference = 'Stop'

$loopback = @('127.0.0.1', '::1')
$srcExe = (Resolve-Path $ExePath).Path
$auditDir = Join-Path $env:RUNNER_TEMP 'pt-no-admin-e2e'
$auditExe = Join-Path $auditDir 'PortableTailscale.exe'

# Random per-run throwaway account; the password meets complexity rules by
# construction (base64 payload + explicit upper/lower/digit/special tail).
$random = New-Object byte[] 12
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$suffix = ([Convert]::ToBase64String($random) -replace '[^a-zA-Z0-9]', '').Substring(0, 10)
$user = "pt_e2e_$suffix"
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$password = [Convert]::ToBase64String($random) + '!aA1'
$taskName = 'PortableTailscaleNoAdminE2E'
$targetPid = $null
$bodyFailed = $false

try {
    # 1. The image must not ask Windows to elevate it.
    $bytes = [System.IO.File]::ReadAllBytes($srcExe)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes) +
        [System.Text.Encoding]::Unicode.GetString($bytes)
    foreach ($level in @('requireAdministrator', 'highestAvailable')) {
        if ($text.Contains($level)) {
            throw "the exe requests UAC elevation: found '$level' in the image"
        }
    }

    # 2. Run the exe headless as a throwaway standard user.
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $user -Password $securePassword -Description 'PortableTailscale no-admin e2e' | Out-Null

    # Stage the exe where the standard user may read and execute it; the
    # runner workspace ACLs do not necessarily allow other local users.
    if (Test-Path $auditDir) { Remove-Item $auditDir -Recurse -Force }
    New-Item -ItemType Directory -Path $auditDir | Out-Null
    Copy-Item $srcExe $auditExe
    icacls $auditDir /grant "${user}:(OI)(CI)RX" /T | Out-Null

    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    # --install binds the loopback proxy before login, so the audit is
    # guaranteed a socket to observe; sign-in is never completed in CI.
    $action = New-ScheduledTaskAction -Execute $auditExe -Argument '--install --no-browser' -WorkingDirectory $auditDir
    Register-ScheduledTask -TaskName $taskName -Action $action -User $user -Password $password | Out-Null
    Get-Process -Name 'PortableTailscale' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $taskName

    $deadline = (Get-Date).AddSeconds(30)
    while (-not $targetPid -and (Get-Date) -lt $deadline) {
        $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'PortableTailscale.exe'" |
            Where-Object { $_.ExecutablePath -eq $auditExe })
        if ($procs.Count -gt 0) { $targetPid = $procs[0].ProcessId }
        else { Start-Sleep -Milliseconds 500 }
    }
    if (-not $targetPid) {
        $result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
        throw ("the exe never started as a standard user (LastTaskResult = 0x{0:X8})" -f $result)
    }
    $owner = Get-CimInstance Win32_Process -Filter "ProcessId = $targetPid" | Invoke-CimMethod -MethodName GetOwner
    if (-not $owner -or $owner.User -ne $user) {
        throw "the audited process is owned by '$($owner.User)', not by the standard user '$user'"
    }
    Write-Host "audit: watching PID $targetPid (user $user) for $Seconds s"

    # 3. Sample the process's sockets for the whole audit window.
    $udpStrikes = @{}
    $sawSocket = $false
    $sawOutbound = $false
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
            $result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
            throw ("the exe exited early while running as {0} (LastTaskResult = 0x{1:X8})" -f $user, $result)
        }
        # One strike per unique non-loopback UDP local address per sample.
        $seen = @{}
        foreach ($ep in @(Get-NetUDPEndpoint -OwningProcess $targetPid -ErrorAction SilentlyContinue)) {
            $sawSocket = $true
            $seen[$ep.LocalAddress] = $true
        }
        foreach ($tcp in @(Get-NetTCPConnection -OwningProcess $targetPid -State Listen -ErrorAction SilentlyContinue)) {
            $sawSocket = $true
            if ($loopback -notcontains $tcp.LocalAddress) {
                throw "non-loopback TCP listener $($tcp.LocalAddress):$($tcp.LocalPort)"
            }
        }
        foreach ($conn in @(Get-NetTCPConnection -OwningProcess $targetPid -State Established -ErrorAction SilentlyContinue)) {
            if ($loopback -notcontains $conn.RemoteAddress) { $sawOutbound = $true }
        }
        foreach ($addr in @($seen.Keys)) {
            if ($loopback -contains $addr) { continue }
            $udpStrikes[$addr] = 1 + [int]$udpStrikes[$addr]
            if ($udpStrikes[$addr] -ge 3) {
                throw ("persistent non-loopback UDP bind on {0} ({1} consecutive samples); this is what triggers the firewall dialog" -f $addr, $udpStrikes[$addr])
            }
        }
        foreach ($addr in @($udpStrikes.Keys)) {
            if (-not $seen.ContainsKey($addr)) { $udpStrikes.Remove($addr) }
        }
        Start-Sleep -Seconds $SampleSeconds
    }
    if (-not $sawSocket) {
        throw 'the audit observed no sockets at all; it was not watching the process'
    }
    if (-not $sawOutbound) {
        throw 'no outbound connection was observed; the tsnet node (control/DERP path) never started'
    }
    Write-Host 'audit: PASS — no elevation requested, no non-loopback binds as a standard user'
}
catch {
    $bodyFailed = $true
    throw
}
finally {
    $cleanupErrors = @()
    if ($targetPid) {
        try { Stop-Process -Id $targetPid -Force -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    }
    try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    try { Remove-LocalUser -Name $user -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    if (Test-Path $auditDir) {
        try { Remove-Item $auditDir -Recurse -Force -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($cleanupErrors.Count -gt 0 -and -not $bodyFailed) {
        throw ("cleanup failed (fail closed): " + ($cleanupErrors -join '; '))
    }
}
