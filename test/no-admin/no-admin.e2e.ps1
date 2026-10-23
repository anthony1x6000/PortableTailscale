# E2E guard: PortableTailscale must never require administrator privileges.
#
# Windows shows the "allow ... on private and public networks" firewall dialog
# the moment a process binds a non-loopback socket, and a standard user cannot
# dismiss that dialog — only an administrator can. So this script proves,
# against the freshly built exe:
#
#   1. the exe does not request UAC elevation (no requireAdministrator or
#      highestAvailable anywhere in its bytes, which covers any embedded
#      manifest),
#   2. it starts and keeps running as a freshly created *standard* user,
#   3. for the whole audit window it never owns a non-loopback TCP listener,
#      and never owns a non-loopback UDP socket that persists across three
#      consecutive samples (a fleeting UDP socket is an outbound client such
#      as a DNS query; those do not trigger the dialog, persistent ones do),
#   4. the audit observed at least one socket of the process, so a blind
#      pass cannot fake success.
#
# Run by .github/workflows/windows-build.yml after the build step.

param(
    [Parameter(Mandatory = $true)] [string] $ExePath,
    [int] $Seconds = 30,
    [int] $SampleSeconds = 2
)

$ErrorActionPreference = 'Stop'

$loopback = @('127.0.0.1', '::1')
$exe = (Resolve-Path $ExePath).Path
$workdir = Split-Path -Parent $exe
# --install binds the loopback proxy before login, so the audit is guaranteed
# a socket to observe; sign-in is never completed in CI.
$exeArgs = '--install --no-browser'
$user = 'pt_noadmin_e2e'
$plainPassword = 'PtE2e!no-admin-2026'
$taskName = 'PortableTailscaleNoAdminE2E'
$targetPid = $null

try {
    # 1. The image must not ask Windows to elevate it.
    $bytes = [System.IO.File]::ReadAllBytes($exe)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes) +
        [System.Text.Encoding]::Unicode.GetString($bytes)
    foreach ($level in @('requireAdministrator', 'highestAvailable')) {
        if ($text.Contains($level)) {
            throw "the exe requests UAC elevation: found '$level' in the image"
        }
    }

    # 2. Run the exe headless as a throwaway standard user.
    Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
    $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
    New-LocalUser -Name $user -Password $securePassword -Description 'PortableTailscale no-admin e2e' | Out-Null
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute $exe -Argument $exeArgs -WorkingDirectory $workdir
    Register-ScheduledTask -TaskName $taskName -Action $action -User $user -Password $plainPassword | Out-Null
    Start-ScheduledTask -TaskName $taskName

    $deadline = (Get-Date).AddSeconds(30)
    while (-not $targetPid -and (Get-Date) -lt $deadline) {
        $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'PortableTailscale.exe'" |
            Where-Object { $_.ExecutablePath -eq $exe })
        if ($procs.Count -gt 0) { $targetPid = $procs[0].ProcessId }
        else { Start-Sleep -Milliseconds 500 }
    }
    if (-not $targetPid) {
        throw 'the exe never started as a standard user (did it demand elevation?)'
    }
    Write-Host "audit: watching PID $targetPid (user $user) for $Seconds s"

    # 3. Sample the process's sockets for the whole audit window.
    $udpStrikes = @{}
    $sawSocket = $false
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
            $result = (Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult
            throw ("the exe exited early while running as {0} (LastTaskResult = 0x{1:X8})" -f $user, $result)
        }
        $seen = @{}
        foreach ($ep in @(Get-NetUDPEndpoint -OwningProcess $targetPid -ErrorAction SilentlyContinue)) {
            $sawSocket = $true
            $addr = $ep.LocalAddress
            $seen[$addr] = $true
            if ($loopback -notcontains $addr) {
                $udpStrikes[$addr] = 1 + [int]$udpStrikes[$addr]
            }
        }
        foreach ($tcp in @(Get-NetTCPConnection -OwningProcess $targetPid -State Listen -ErrorAction SilentlyContinue)) {
            $sawSocket = $true
            if ($loopback -notcontains $tcp.LocalAddress) {
                throw "non-loopback TCP listener $($tcp.LocalAddress):$($tcp.LocalPort)"
            }
        }
        foreach ($addr in @($udpStrikes.Keys)) {
            if (-not $seen.ContainsKey($addr)) { $udpStrikes.Remove($addr) }
        }
        Start-Sleep -Seconds $SampleSeconds
    }
    foreach ($addr in @($udpStrikes.Keys)) {
        if ($udpStrikes[$addr] -ge 3) {
            throw ("persistent non-loopback UDP bind on {0} ({1} consecutive samples); this is what triggers the firewall dialog" -f $addr, $udpStrikes[$addr])
        }
    }
    if (-not $sawSocket) {
        throw 'the audit observed no sockets at all; it was not watching the process'
    }
    Write-Host 'audit: PASS — no elevation requested, no non-loopback binds as a standard user'
}
finally {
    if ($targetPid) { Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue }
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
}
