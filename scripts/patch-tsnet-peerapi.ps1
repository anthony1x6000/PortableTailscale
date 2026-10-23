# Patches the pinned tsnet module in the Go module cache so its userspace
# (netstack) peerapi listener does not bind 0.0.0.0 on the host.
#
# Why: tailscale v1.102.5's ipn/ipnlocal/peerapi.go blanks the bind address
# for netstack builds ("ipStr = \"\""), which binds a real kernel listener on
# every interface at a deterministic port the moment the netmap arrives. On
# Windows that is exactly what triggers the "allow ... on private and public
# networks" firewall dialog, which standard users cannot dismiss. Upstream's
# own fakePeerAPIListener (the Android path) is the correct behavior for
# netstack: netstack intercepts peerapi traffic regardless, so the kernel
# listener is vestigial. Until upstream ships that, builds patch the module in
# place. The anchor check fails loudly when the pinned version changes so the
# patch gets revisited instead of silently skipped.
#
# Idempotent: safe to run on an already-patched cache (CI restores one).

$ErrorActionPreference = 'Stop'

$null = go mod download
$ver = (go list -m -f '{{.Version}}' tailscale.com).Trim()
$file = "$(go env GOMODCACHE)/tailscale.com@$ver/ipn/ipnlocal/peerapi.go"
if (-not (Test-Path $file)) { throw "peerapi.go not found at $file" }

$src = Get-Content $file -Raw
$anchor = "if s.b.sys.IsNetstack() {`n`t`tipStr = `"`"`n`t}"
$patched = "if s.b.sys.IsNetstack() {`n`t`treturn newFakePeerAPIListener(ip), nil`n`t}"
if ($src.Contains($patched)) {
    Write-Host "tsnet peerapi already patched ($ver)"
    exit 0
}
if (-not $src.Contains($anchor)) {
    throw "tsnet peerapi patch anchor not found in $file; the pinned tailscale version ($ver) changed upstream code. Re-derive the patch."
}

# The module cache is read-only by design; make the one file writable, patch
# it in place, and verify the exact patched form came out.
$item = Get-Item $file
$item.IsReadOnly = $false
Set-Content -Path $file -Value $src.Replace($anchor, $patched) -NoNewline
$check = Get-Content $file -Raw
if (-not $check.Contains($patched) -or $check.Contains($anchor)) {
    throw "tsnet peerapi patch did not apply cleanly to $file; refusing to build an unverified patch."
}
Write-Host "tsnet peerapi patched for loopback-only userspace nodes ($ver)"
