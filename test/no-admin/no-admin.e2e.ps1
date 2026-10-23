# E2E guard: PortableTailscale must never require administrator privileges.
#
# Windows shows the "allow ... on private and public networks" firewall dialog
# when a process owns a non-loopback listening socket, and a standard user
# cannot dismiss that dialog — only an administrator can. So this script
# proves, against the freshly built exe:
#
#   1. the exe does not request UAC elevation (no requireAdministrator or
#      highestAvailable anywhere in its bytes, which covers any embedded
#      manifest),
#   2. it starts and keeps running as a freshly created *standard* user,
#      from a directory that user may execute (the runner workspace is not
#      readable by arbitrary local users),
#   3. during the whole audit window it never owns a non-loopback socket of
#      any kind: no non-loopback TCP listener, and no non-loopback UDP
#      endpoint at all (zero tolerance — even a brief wildcard UDP bind can
#      trigger the dialog). The expected UDP set is loopback-only (netcheck
#      binds [::1]); the WireGuard and portmapper sockets this PR guards
#      against are bound at tsnet engine start, before any login, so the
#      pre-login audit window covers them (magicsock bindSocket runs at
#      engine start; the portmapper socket is created during the endpoint
#      determination that engine start triggers),
#   4. the audit observed the process actually networking (an established
#      outbound TCP connection is the Tailscale control/DERP path, so the
#      engine really started) and observed at least one of its sockets, so
#      a blind or wrong-process pass cannot fake success.
#
# Socket queries run unfiltered and are filtered client-side by owning PID:
# the NetTCPIP cmdlets report a no-match filter as an error, which would
# turn an empty sample into a false failure; client-side filtering makes an
# empty sample an empty set while a real query failure still throws.
# Credentials for the throwaway local user are generated at random per run
# and never leave memory; cleanup failures are always reported and fail a
# passing run.
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
# Root of the system drive, not a user profile tree: the runner's profile
# ACLs do not necessarily allow other local users even with an explicit
# grant, and a profile Temp dir adds another moving part.
$auditDir = 'C:\pt-no-admin-e2e'
$auditExe = Join-Path $auditDir 'PortableTailscale.exe'

# Random per-run throwaway account; the password meets complexity rules by
# construction (base64 payload + explicit upper/lower/digit/special tail).
$random = New-Object byte[] 12
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$suffix = ([Convert]::ToBase64String($random) -replace '[^a-zA-Z0-9]', '').Substring(0, 10)
$user = "pt_e2e_$suffix"
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$password = [Convert]::ToBase64String($random) + '!aA1'
$targetProc = $null
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

    # 2. Run the exe as a throwaway standard user.
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $user -Password $securePassword -Description 'PortableTailscale no-admin e2e' | Out-Null

    # Stage the exe where the standard user may read and execute it; the
    # runner workspace ACLs do not necessarily allow other local users.
    if (Test-Path $auditDir) { Remove-Item $auditDir -Recurse -Force }
    New-Item -ItemType Directory -Path $auditDir | Out-Null
    Copy-Item $srcExe $auditExe
    icacls $auditDir /grant "${user}:(OI)(CI)RX" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls grant for $user failed with exit code $LASTEXITCODE" }

    Get-Process -Name 'PortableTailscale' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    # CreateProcessWithLogonW (what runas uses): launches the exe directly as
    # the standard user, headless, with that user's profile loaded. A
    # scheduled task was tried and never left the "has not run" state on the
    # runner (0x41303); this path has no scheduler in the way.
    $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)
    # --install binds the loopback proxy before login, so the audit is
    # guaranteed a socket to observe; sign-in is never completed in CI.
    $targetProc = Start-Process -FilePath $auditExe -ArgumentList '--install', '--no-browser' -WorkingDirectory $auditDir -Credential $credential -LoadUserProfile -WindowStyle Hidden -PassThru
    $targetPid = $targetProc.Id
    # WMI can lag process creation by a moment; poll for the instance and
    # the owner instead of demanding it in the same millisecond.
    $deadline = (Get-Date).AddSeconds(15)
    $owner = $null
    while ((Get-Date) -lt $deadline) {
        $targetProc.Refresh()
        if ($targetProc.HasExited) {
            throw ("the exe exited early while running as {0} (exit code {1})" -f $user, $targetProc.ExitCode)
        }
        $instance = Get-CimInstance Win32_Process -Filter "ProcessId = $targetPid"
        if ($instance) {
            $owner = $instance | Invoke-CimMethod -MethodName GetOwner
            if ($owner -and $owner.User -eq $user) { break }
        }
        Start-Sleep -Milliseconds 500
    }
    if (-not $owner -or $owner.User -ne $user) {
        throw "could not confirm the audited process runs as the standard user '$user'"
    }
    Write-Host "audit: watching PID $targetPid (user $user) for $Seconds s"

    # 3. Sample the process's sockets for the whole audit window.
    $sawSocket = $false
    $sawOutbound = $false
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $targetProc.Refresh()
        if ($targetProc.HasExited) {
            throw ("the exe exited early while running as {0} (exit code {1})" -f $user, $targetProc.ExitCode)
        }
        foreach ($ep in @(Get-NetUDPEndpoint | Where-Object { $_.OwningProcess -eq $targetPid })) {
            $sawSocket = $true
            if ($loopback -notcontains $ep.LocalAddress) {
                throw ("non-loopback UDP endpoint {0}:{1}; any non-loopback UDP socket can trigger the firewall dialog" -f $ep.LocalAddress, $ep.LocalPort)
            }
        }
        foreach ($tcp in @(Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $targetPid -and $_.State -eq 'Listen' })) {
            $sawSocket = $true
            if ($loopback -notcontains $tcp.LocalAddress) {
                throw "non-loopback TCP listener $($tcp.LocalAddress):$($tcp.LocalPort)"
            }
        }
        foreach ($conn in @(Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $targetPid -and $_.State -eq 'Established' })) {
            if ($loopback -notcontains $conn.RemoteAddress) { $sawOutbound = $true }
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
    if ($targetProc -and -not $targetProc.HasExited) {
        try { Stop-Process -Id $targetProc.Id -Force -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    }
    try { Remove-LocalUser -Name $user -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    if (Test-Path $auditDir) {
        try { Remove-Item $auditDir -Recurse -Force -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($cleanupErrors.Count -gt 0) {
        Write-Warning ("cleanup failed: " + ($cleanupErrors -join '; '))
        if (-not $bodyFailed) {
            throw 'cleanup failed on an otherwise passing run; failing closed'
        }
    }
}
