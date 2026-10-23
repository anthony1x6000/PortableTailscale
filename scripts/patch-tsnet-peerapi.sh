#!/bin/sh
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

set -eu

go mod download
ver=$(go list -m -f '{{.Version}}' tailscale.com)
file="$(go env GOMODCACHE)/tailscale.com@$ver/ipn/ipnlocal/peerapi.go"
[ -f "$file" ] || { echo "peerapi.go not found at $file" >&2; exit 1; }

patched_re='\tif s\.b\.sys\.IsNetstack\(\) \{\n\t\treturn newFakePeerAPIListener\(ip\), nil\n\t\}'
anchor_re='\tif s\.b\.sys\.IsNetstack\(\) \{\n\t\tipStr = ""\n\t\}'

if perl -0777 -ne "exit(/$patched_re/ ? 0 : 1)" "$file"; then
	echo "tsnet peerapi already patched ($ver)"
	exit 0
fi
if ! perl -0777 -ne "exit(/$anchor_re/ ? 0 : 1)" "$file"; then
	echo "tsnet peerapi patch anchor not found in $file; the pinned tailscale version ($ver) changed upstream code. Re-derive the patch." >&2
	exit 1
fi

# The module cache is read-only by design; make the one file writable, patch
# it in place (through a temp file, since the directory stays read-only), and
# verify the exact patched form came out.
chmod u+w "$file"
tmp=$(mktemp)
perl -0777 -pe "s/$anchor_re/\tif s.b.sys.IsNetstack() {\n\t\treturn newFakePeerAPIListener(ip), nil\n\t}/" "$file" > "$tmp"
cat "$tmp" > "$file"
rm -f "$tmp"
# The patched block must be present and the anchored original gone. (A second,
# unrelated "ipStr = \"\"" exists in the darwin/ios branch, so the check is on
# the exact three-line blocks, not the bare assignment.)
if ! perl -0777 -ne "exit(/$patched_re/ ? 0 : 1)" "$file" || perl -0777 -ne "exit(/$anchor_re/ ? 0 : 1)" "$file"; then
	echo "tsnet peerapi patch did not apply cleanly to $file; refusing to build an unverified patch." >&2
	exit 1
fi
echo "tsnet peerapi patched for loopback-only userspace nodes ($ver)"
