# E2E guard: PortableTailscale must never require administrator privileges on
# Windows, and must actually work — headless login, connected state, and a
# proxied fetch of a tailnet URL — as a standard user, with no secrets.
#
# A private Tailscale world runs on loopback (test/harness): a fake control
# server that accepts any auth key, a DERP server, and a peer node serving a
# known payload over its tailnet address. The freshly built exe is driven
# through the real user flow against it:
#
#   1. the exe must not request UAC elevation (no requireAdministrator or
#      highestAvailable anywhere in its bytes, covering any embedded manifest),
#   2. it runs as a freshly created *standard* user, from a directory that
#      user may write (the runner workspace is not readable by arbitrary
#      local users), with a writable TEMP (CreateProcessWithLogonW inherits
#      the parent's, which points at the runner admin's profile),
#   3. from launch through connected state it never owns a non-loopback
#      socket in any sample: no non-loopback TCP listener and no non-loopback
#      UDP endpoint at all — a single sighting fails the run. The guarded
#      sockets (magicsock's WireGuard UDP, the UPnP portmapper, upstream DNS)
#      are bound from engine start onward and live for the process lifetime,
#      well above the sample interval; sub-second binds cannot be excluded by
#      sampling, and the README documents the one remaining known path,
#   4. it reaches the connected event (login completes headlessly), binds
#      the loopback HTTP proxy on 127.0.0.1:41112, and curl through that
#      proxy fetches the harness peer's payload by short name and by FQDN —
#      the exact user-facing acceptance criteria.
#
# The exe runs with --install so the loopback proxy and PAC flow execute;
# the fixed port 41112 is only bound on loopback, where runner port
# exclusions do not apply. Its --json output is captured through a cmd
# wrapper (Start-Process cannot combine -Credential with redirection).
#
# Socket queries run unfiltered and are filtered client-side by owning PID:
# the NetTCPIP cmdlets report a no-match filter as an error, which would
# turn an empty sample into a false failure; client-side filtering makes an
# empty sample an empty set while a real query failure still throws.
#
# Run by .github/workflows/windows-build.yml after the build step.

param(
    [Parameter(Mandatory = $true)] [string] $ExePath,
    [Parameter(Mandatory = $true)] [string] $HarnessPath,
    [int] $LoginTimeoutSeconds = 120,
    [int] $PostConnectSeconds = 20,
    [int] $SampleSeconds = 1
)

$ErrorActionPreference = 'Stop'

$loopback = @('127.0.0.1', '::1')
$srcExe = (Resolve-Path $ExePath).Path
$srcHarness = (Resolve-Path $HarnessPath).Path
# Root of the system drive, not a user profile tree: profile ACLs do not
# necessarily allow other local users even with an explicit grant.
$auditDir = 'C:\pt-no-admin-e2e'
$auditExe = Join-Path $auditDir 'PortableTailscale.exe'
$auditHarness = Join-Path $auditDir 'pt-e2e-harness.exe'
$outLog = Join-Path $auditDir 'out.log'
$harnessLog = Join-Path $auditDir 'harness.log'

# Random per-run throwaway account; the password meets complexity rules by
# construction (base64 payload + explicit upper/lower/digit/special tail).
$random = New-Object byte[] 12
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$suffix = ([Convert]::ToBase64String($random) -replace '[^a-zA-Z0-9]', '').Substring(0, 10)
$user = "pt_e2e_$suffix"
[System.Security.Cryptography.RandomNumberGenerator]::Fill($random)
$password = [Convert]::ToBase64String($random) + '!aA1'
$harnessProc = $null
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
    # Dumped output sanitized for public CI logs: any absolute or
    # credentialed URL (sign-in URLs enroll the pending node, SOCKS5 URLs
    # carry generated passwords) and raw tskey- auth keys are redacted.
    if (Test-Path $outLog) {
        $raw = Get-Content $outLog -Raw -ErrorAction SilentlyContinue
        return (($raw -replace '(?i)\b[a-z][a-z0-9+.\-]*://\S+', '[url]') -replace 'tskey-\S+', '[authkey]')
    }
    return 'no output captured'
}

function ConvertTo-SafeEvents {
    # Event names are exe-controlled data; sanitize them the same way as
    # Get-LogDetail so a hostile value cannot smuggle a credential into
    # public CI logs via the "events seen" diagnostics.
    param([Parameter(Mandatory = $true)] $Events)
    return ((($Events.Keys | Sort-Object) -join ',') -replace '(?i)\b[a-z][a-z0-9+.\-]*://\S+', '[url]') -replace 'tskey-\S+', '[authkey]'
}

function Assert-AuditSample {
    # One socket sample for the audited PID: every UDP endpoint and every
    # TCP listener must be loopback; tracks whether any socket and any
    # outbound connection were ever seen.
    foreach ($ep in @(Get-NetUDPEndpoint | Where-Object { $_.OwningProcess -eq $script:targetPid })) {
        $script:sawSocket = $true
        if ($loopback -notcontains $ep.LocalAddress) {
            throw ("non-loopback UDP endpoint {0}:{1}; any non-loopback UDP socket can trigger the firewall dialog" -f $ep.LocalAddress, $ep.LocalPort)
        }
    }
    foreach ($tcp in @(Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $script:targetPid -and $_.State -eq 'Listen' })) {
        $script:sawSocket = $true
        if ($loopback -notcontains $tcp.LocalAddress) {
            throw "non-loopback TCP listener $($tcp.LocalAddress):$($tcp.LocalPort)"
        }
    }
    foreach ($conn in @(Get-NetTCPConnection | Where-Object { $_.OwningProcess -eq $script:targetPid -and $_.State -eq 'Established' })) {
        if ($loopback -notcontains $conn.RemoteAddress) { $script:sawOutbound = $true }
    }
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

    # 2. Stage everything and prepare the standard user.
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
    New-LocalUser -Name $user -Password $securePassword -Description 'PortableTailscale no-admin e2e' | Out-Null

    if (Test-Path $auditDir) { Remove-Item $auditDir -Recurse -Force }
    New-Item -ItemType Directory -Path $auditDir | Out-Null
    Copy-Item $srcExe $auditExe
    Copy-Item $srcHarness $auditHarness
    icacls $auditDir /grant "${user}:(OI)(CI)M" /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls grant for $user failed with exit code $LASTEXITCODE" }
    $tmpDir = Join-Path $auditDir 'tmp'
    New-Item -ItemType Directory -Path $tmpDir | Out-Null

    # The harness (fake control + DERP + peer) runs as the runner user on
    # loopback; the exe as the standard user reaches it over loopback.
    $harnessProc = Start-Process -FilePath $auditHarness -WorkingDirectory $auditDir -WindowStyle Hidden -RedirectStandardOutput $harnessLog -RedirectStandardError (Join-Path $auditDir 'harness.err') -PassThru
    $world = @{}
    $deadline = (Get-Date).AddSeconds(60)
    while (-not $world.ContainsKey('ready') -and (Get-Date) -lt $deadline) {
        if (Test-Path $harnessLog) {
            foreach ($line in @(Get-Content $harnessLog -ErrorAction SilentlyContinue)) {
                $k, $v = $line -split '=', 2
                if ($k -and $v) { $world[$k] = $v }
            }
        }
        if (-not $world.ContainsKey('ready')) { Start-Sleep -Milliseconds 500 }
    }
    if (-not $world.ContainsKey('ready')) {
        throw "the e2e harness never became ready; harness output: $((Get-Content $harnessLog -Raw -ErrorAction SilentlyContinue))"
    }
    Write-Host "audit: harness world ready (control $($world['control']), peer $($world['peer-short']) / $($world['peer-fqdn']))"

    Get-Process -Name 'PortableTailscale' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    # cmd /c runs the exe and redirects its output where we can read it;
    # Start-Process -Credential (CreateProcessWithLogonW) cannot redirect
    # itself. Paths have no spaces, so the command line stays quote-free —
    # PowerShell 7.3+ re-quotes ArgumentList elements that contain quotes
    # and hands cmd mangled input. The child inherits the parent step's
    # TEMP/TMP (the runner admin's profile), which the standard user cannot
    # write, so the environment points at directories it owns. TS_AUTHKEY
    # carries a fake key for the local test control server; there is no
    # secret anywhere.
    $cmdLine = 'set TS_AUTHKEY=e2e-key& set TMP={0}& set TEMP={0}& set USERPROFILE=C:\Users\{1}& {2} --install --no-browser --json --control-url {3} > {4} 2>&1' -f $tmpDir, $user, $auditExe, $world['control'], $outLog
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
    Write-Host "audit: watching PID $targetPid (user $user)"

    # 3. Audit from launch through the login timeout: every sample must be
    # clean, and the connected event must arrive (headless login against the
    # fake control).
    $sawSocket = $false
    $sawOutbound = $false
    $sawConnected = $false
    $deadline = (Get-Date).AddSeconds($LoginTimeoutSeconds)
    while (-not $sawConnected -and (Get-Date) -lt $deadline) {
        $alive = Get-Process -Id $targetPid -ErrorAction SilentlyContinue
        if (-not $alive -or $alive.Name -ne 'PortableTailscale') {
            throw ("the exe exited early (or its PID was reused) while running as $user; output: {0}" -f (Get-LogDetail))
        }
        Assert-AuditSample
        if ((Read-Events).ContainsKey('connected')) { $sawConnected = $true }
        else { Start-Sleep -Seconds $SampleSeconds }
    }
    if (-not $sawConnected) {
        throw ("the exe never reached the connected state (events seen: {0}); netstat: {1}; output tail: {2}" -f (ConvertTo-SafeEvents (Read-Events)), ((netstat.exe -ano | Select-String $targetPid) -join ' | '), ((Get-LogDetail) -split "`n" | Select-Object -Last 5))
    }
    Write-Host 'audit: connected reached; auditing the post-login window'

    # 4. Post-login audit window.
    $deadline = (Get-Date).AddSeconds($PostConnectSeconds)
    while ((Get-Date) -lt $deadline) {
        Assert-AuditSample
        Start-Sleep -Seconds $SampleSeconds
    }
    if (-not $sawSocket) {
        throw "connected but no socket of the process was ever observed; the audit was not watching the right process. netstat: $((netstat.exe -ano | Select-String $targetPid) -join ' | ')"
    }
    if (-not $sawOutbound) {
        throw 'connected but no outbound connection was observed; the control/DERP path never ran'
    }

    # 5. The user-facing promise: a tailnet URL through the loopback proxy.
    foreach ($hostName in @($world['peer-short'], $world['peer-fqdn'])) {
        $url = 'http://{0}:{1}/' -f $hostName, $world['peer-port']
        $body = & curl.exe -s --max-time 30 -x "http://127.0.0.1:41112" $url
        if ($LASTEXITCODE -ne 0 -or "$body" -ne $world['payload']) {
            throw ("fetch through the loopback proxy failed for {0} (curl exit {1}, body '{2}'); output tail: {3}" -f $url, $LASTEXITCODE, $body, ((Get-LogDetail) -split "`n" | Select-Object -Last 5))
        }
        Write-Host "audit: proxied fetch OK: $url"
    }
    Write-Host 'audit: PASS — standard user, no elevation, no non-loopback binds, tailnet URL served through the proxy'
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
    if ($harnessProc -and -not $harnessProc.HasExited) {
        try { Stop-Process -Id $harnessProc.Id -Force -ErrorAction Stop } catch { $cleanupErrors += $_.Exception.Message }
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
