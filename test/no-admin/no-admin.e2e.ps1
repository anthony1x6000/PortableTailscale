# E2E guard: PortableTailscale must never require administrator privileges,
# on Windows, from startup through the post-login data path.
#
# Windows shows the "allow ... on private and public networks" firewall dialog
# when a process owns a non-loopback listening socket, and a standard user
# cannot dismiss that dialog — only an administrator can. This script proves,
# against the freshly built exe:
#
#   1. the exe does not request UAC elevation (no requireAdministrator or
#      highestAvailable anywhere in its bytes, covering any embedded manifest),
#   2. it runs as a freshly created *standard* user, from a directory that
#      user may write (the runner workspace is not readable by arbitrary
#      local users), and keeps running for the whole audit window,
#   3. it never owns a non-loopback socket in any sample: no non-loopback TCP
#      listener and no non-loopback UDP endpoint at all — a single sighting
#      fails the run. The guarded sockets — magicsock's WireGuard UDP, the
#      UPnP portmapper, and any DNS-forwarder UDP — are bound from engine
#      start onward and live for the process lifetime, well above the sample
#      interval; sub-second binds cannot be excluded by sampling, and the
#      README documents the one remaining known path (upstream DNS via
#      SOCKS5 to non-tailnet names),
#   4. it actually progresses: the log must show the sign-in URL event (or,
#      when the TS_AUTHKEY secret is provided, the connected event), an
#      established outbound connection to Tailscale control/DERP, and at
#      least one socket of the process, so a blind or wrong-process pass
#      cannot fake success.
#
# The exe runs without --install so the fixed loopback proxy port is not
# involved: runner images can have WinNAT/Hyper-V excluded port ranges that
# make binding one specific port fail, which says nothing about admin rights.
# Its --json output is captured through a cmd wrapper (Start-Process cannot
# combine -Credential with output redirection) and parsed for the events.
#
# Socket queries run unfiltered and are filtered client-side by owning PID:
# the NetTCPIP cmdlets report a no-match filter as an error, which would turn
# an empty sample into a false failure; client-side filtering makes an empty
# sample an empty set while a real query failure still throws.
#
# Run by .github/workflows/windows-build.yml after the build step.

param(
    [Parameter(Mandatory = $true)] [string] $ExePath,
    [int] $Seconds = 60,
    [int] $SampleSeconds = 1
)

$ErrorActionPreference = 'Stop'

$loopback = @('127.0.0.1', '::1')
$srcExe = (Resolve-Path $ExePath).Path
# Root of the system drive, not a user profile tree: profile ACLs do not
# necessarily allow other local users even with an explicit grant.
$auditDir = 'C:\pt-no-admin-e2e'
$auditExe = Join-Path $auditDir 'PortableTailscale.exe'
$outLog = Join-Path $auditDir 'out.log'
$haveAuthKey = -not [string]::IsNullOrEmpty($env:TS_AUTHKEY)

# Random per-run throwaway account; the password meets complexity rules by
# construction (base64 payload + explicit upper/lower/digit/special tail).
$random = New-Object byte[] 12
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$suffix = ([Convert]::ToBase64String($random) -replace '[^a-zA-Z0-9]', '').Substring(0, 10)
$user = "pt_e2e_$suffix"
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$password = [Convert]::ToBase64String($random) + '!aA1'
$cmdProc = $null
$targetPid = $null
$bodyFailed = $false

function Read-Events {
    # Returns the set of --json event names seen in the captured output so
    # far; non-JSON lines (stderr mixed into the same file) are ignored.
    $events = @{}
    if (Test-Path $outLog) {
        foreach ($line in @(Get-Content $outLog -ErrorAction SilentlyContinue)) {
            try {
                $obj = $line | ConvertFrom-Json -ErrorAction Stop
                if ($obj.event) { $events[$obj.event] = $true }
            } catch { }
        }
    }
    return $events
}

function Get-LogDetail {
    # Dumped output with URLs redacted: the sign-in URL is a credential for
    # the pending node enrollment and must not land in public CI logs.
    if (Test-Path $outLog) {
        return ((Get-Content $outLog -Raw -ErrorAction SilentlyContinue) -replace 'https?://\S+', '[url]')
    }
    return 'no output captured'
}

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

    if (Test-Path $auditDir) { Remove-Item $auditDir -Recurse -Force }
    New-Item -ItemType Directory -Path $auditDir | Out-Null
    Copy-Item $srcExe $auditExe
    icacls $auditDir /grant "${user}:(OI)(CI)M" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls grant for $user failed with exit code $LASTEXITCODE" }

    Get-Process -Name 'PortableTailscale' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    # cmd /c runs the exe and redirects its output where we can read it;
    # Start-Process -Credential (CreateProcessWithLogonW) cannot redirect
    # itself. Paths have no spaces, so the command line stays quote-free —
    # PowerShell 7.3+ re-quotes ArgumentList elements that contain quotes
    # and hands cmd mangled input. cmd stays alive as the exe's parent while
    # the exe runs.
    $cmdLine = '{0} --no-browser --json > {1} 2>&1' -f $auditExe, $outLog
    $credential = New-Object System.Management.Automation.PSCredential($user, $securePassword)
    $cmdProc = Start-Process -FilePath "$env:ComSpec" -ArgumentList "/c $cmdLine" -WorkingDirectory $auditDir -Credential $credential -LoadUserProfile -WindowStyle Hidden -PassThru
    $cmdPid = $cmdProc.Id

    $deadline = (Get-Date).AddSeconds(30)
    while (-not $targetPid -and (Get-Date) -lt $deadline) {
        $procs = @(Get-CimInstance Win32_Process -Filter "Name = 'PortableTailscale.exe'" |
            Where-Object { $_.ParentProcessId -eq $cmdPid })
        if ($procs.Count -gt 0) { $targetPid = $procs[0].ProcessId }
        else { Start-Sleep -Milliseconds 500 }
    }
    if (-not $targetPid) {
        throw ("the exe never started as a standard user; output: {0}" -f (Get-LogDetail))
    }
    $instance = Get-CimInstance Win32_Process -Filter "ProcessId = $targetPid"
    $owner = $instance | Invoke-CimMethod -MethodName GetOwner
    if (-not $owner -or $owner.User -ne $user) {
        throw "the audited process is owned by '$($owner.User)', not by the standard user '$user'"
    }
    Write-Host "audit: watching PID $targetPid (user $user) for $Seconds s (auth key: $haveAuthKey)"

    # 3. Sample the process's sockets for the whole audit window.
    $sawSocket = $false
    $sawOutbound = $false
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (-not (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
            throw ("the exe exited early while running as $user; output: {0}" -f (Get-LogDetail))
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

    # 4. The node must have reached sign-in, or fully connected with a key.
    $events = Read-Events
    if ($haveAuthKey) {
        if (-not $events.ContainsKey('connected')) {
            throw ("TS_AUTHKEY was provided but the exe never reached the connected state; events seen: {0}; output tail: {1}" -f ($events.Keys -join ','), ((Get-LogDetail) -split "`n" | Select-Object -Last 5))
        }
    }
    elseif (-not $events.ContainsKey('auth')) {
        throw ("the exe never printed a sign-in URL; events seen: {0}" -f ($events.Keys -join ','))
    }
    Write-Host 'audit: PASS — no elevation requested, no non-loopback binds as a standard user'
}
catch {
    $bodyFailed = $true
    throw
}
finally {
    $cleanupErrors = @()
    if ($targetPid -and (Get-Process -Id $targetPid -ErrorAction SilentlyContinue)) {
        try { Stop-Process -Id $targetPid -Force -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($cmdProc) {
        $cmdProc.Refresh()
        if (-not $cmdProc.HasExited) {
            try { Stop-Process -Id $cmdProc.Id -Force -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
        }
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
