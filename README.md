# PortableTailscale

PortableTailscale runs an **ephemeral** Tailscale node in userspace and gives a
Windows desktop automatic access to tailnet machines by name. It is a single
executable and runs as a regular user, without a TUN driver or administrator
rights — on Windows it never triggers the firewall's "allow on public and
private networks" prompt.

It provides three things:

- a loopback SOCKS5 proxy (`socks5://tsnet:PASSWORD@127.0.0.1:PORT`),
- a loopback HTTP proxy plus PAC file so Chromium browsers (Chrome, Edge) can
  open `http://magicdns-name:8080/` directly,
- a managed SSH `ProxyCommand` so `ssh magicdns-name` works without extra tools.

Every run is a fresh, ephemeral Tailscale node. You sign in again each time and
no device identity is written to disk. Closing the program removes the
credentials and every tunnel.

## Quick start

1. Run `PortableTailscale.exe --install` once. Complete the Tailscale sign-in
   (GitHub, Google, Microsoft, or whatever your tailnet uses).
2. Restart Chrome or Edge once so it reads the new proxy configuration.
3. On later runs, just start `PortableTailscale.exe`, sign in, and use:

   ```text
   http://magicdns-name:8080/
   ssh magicdns-name
   ```

4. Keep the window open. Closing it stops the proxies and SSH access.

`--install` is a one-time setup; it also starts the proxy for that run. Use
`--uninstall` to remove the browser and SSH configuration.

## How automatic access works

When `--install` has been used (or a previous install is detected), PortableTailscale starts an HTTP proxy on `127.0.0.1:41112` after sign-in and serves a PAC file listing the tailnet peers it can see.

- **Browsers:** Chromium reads the per-user system proxy configuration. The PAC
  lists only the peers in the current tailnet map (short names, FQDNs, and
  Tailscale IPs); everything else is `DIRECT`. The proxy resolves the name
  through Tailscale and forwards the TCP stream. HTTP and HTTPS traffic work.
- **SSH:** `--install` prepends a marker-managed block to
  `%USERPROFILE%\.ssh\config`. `ssh`, `scp`, and `sftp` then run
  `PortableTailscale.exe --stdio %h %p`, which tunnels through the same local
  proxy.
- **SOCKS5:** the authenticated SOCKS5 URL is still printed for applications
  that speak SOCKS5 directly.

The browser backup is stored in `data/browser-proxy.json`. `--uninstall` restores
the previous PAC setting and removes the SSH block.

### Browser notes

- Chrome and Edge use the system proxy by default; that is what `--install`
  configures.
- Restart the browser after the first `--install`. Chromium caches proxy
  configuration.
- Firefox only works if it is set to **Use system proxy settings**; the manual
  proxy mode cannot use the PAC file.
- Corporate proxy policies (`ProxySettings`, `ProxyMode`) can override the
  per-user setting. PortableTailscale cannot bypass them.
- The PAC URL changes on every run and carries a per-run token, so a local
  process cannot serve a PAC without knowing it. On a normal exit the previous
  proxy setting is restored, so no PAC is left pointing at a dead port. After a
  crash, the stale PAC fails to load and Chromium falls back to a direct
  connection; ordinary internet browsing keeps working and tailnet names do not.
- The loopback proxy has no authentication (Chromium cannot send SOCKS or proxy
  credentials). It only dials peers listed in the tailnet map and is reachable
  only from the local machine; any local user or process that can reach the
  loopback port can use it while PortableTailscale is running.

### SSH notes

- The managed block is prepended so its `ProxyCommand` wins over later blocks
  (OpenSSH uses the first value it finds).
- If you move the executable, run `--install` again so the path is refreshed.
- Tailscale SSH on the remote host sees the **ephemeral node** as the client.
  Because that node belongs to your Tailscale user, ACLs must allow your user or
  `autogroup:member`, not a fixed device name or IP.
- Ordinary SSH servers still use their normal keys or passwords.

## Login and ephemeral identity

- Every run creates a new Tailscale node with in-memory state. The sign-in URL
  opens in your browser (use `--no-browser` to print it instead).
- The node is registered as **ephemeral**; it disappears from the admin console
  after it goes offline.
- Nothing is persisted: no device key, no `tailscaled.state`, no session token.
- Temporary files live under `%TEMP%\portable-tailscale-*` and are deleted on a
  clean exit. Leftovers from a crash are removed at the next startup when they
  are older than 24 hours.
- If `TS_AUTHKEY` is set in the environment, tsnet uses it instead of an
  interactive login. That is outside the supported flow and keeps a longer-lived
  credential in your environment.

Existing installations may still have `data/tailscaled.state` from an earlier
version. It is no longer read; a startup warning points at it. Delete it if you
do not want the old identity on disk, and revoke that device in the Tailscale
admin console.

## Usage limits

This is a proxy, not a system VPN. It deliberately does not install a TUN
adapter, change system DNS, or require administrator rights.

- **Windows:** the program never binds a non-loopback socket. Binding one is
  what makes Windows show the "allow on private and public networks" firewall
  dialog, which a standard user cannot dismiss, so on Windows the Tailscale
  node gives up its direct UDP paths: all tailnet traffic is relayed through
  Tailscale's DERP servers and never uses LAN-direct connections. This is the
  price of running with no administrator rights at all; CI enforces it with an
  end-to-end audit (`test/no-admin/no-admin.e2e.ps1`).
- **Covered:** Chromium browsers using the system proxy, SSH/SCP/SFTP through the
  managed `ProxyCommand`, and any app you point at the loopback HTTP proxy, e.g.
  `curl -x http://127.0.0.1:41112 http://magicdns-name:8080/`.
- **Not covered:** arbitrary TCP/UDP sockets, `ping`, apps that ignore the system
  proxy or their own proxy settings, and tools that resolve names locally before
  connecting.
- The program must be running. When automatic access is installed, it binds
  `127.0.0.1:41112`; a second instance fails with a clear error.
- The loopback HTTP proxy has no authentication. Any local process can use it
  while the program runs. It only dials tailnet peers, IPs, and `*.ts.net` names,
  so it cannot be used as an open internet proxy.
- TCP only; UDP is not proxied.
- MagicDNS must be enabled: both short peer names and `*.ts.net` names are
  resolved through the tailnet resolver.
- The target service must listen on the tailnet interface (not only
  `127.0.0.1`), its firewall must allow the port, and tailnet ACLs must allow
  your user.
- Because every run is a new node, ACL rules that name the old device or its IP
  stop matching. Use user or group rules.
- Security boundary: PortableTailscale is designed for a single-user desktop.
  Chromium cannot authenticate to a loopback HTTP proxy, so the proxy accepts
  local connections without credentials and relies on the tailnet peer
  allow-list. Do not run it on a host where untrusted local users can reach
  `127.0.0.1`.

## SOCKS5 proxy

The authenticated SOCKS5 URL has this format:

```text
socks5://tsnet:PASSWORD@127.0.0.1:PORT
```

A new port and password are generated each run. Use it with any application
that supports an authenticated SOCKS5 proxy. Browsers cannot send SOCKS5
credentials, which is why the PAC/HTTP proxy exists.

## RDP example

`PortableTailscaleRDP.exe` is an example client included with the project. It
starts PortableTailscale and opens the bundled FreeRDP client through the
authenticated SOCKS5 proxy. Since each launch starts an ephemeral node, expect
a Tailscale sign-in each time as well.

1. Place `PortableTailscaleRDP.exe` beside `PortableTailscale.exe`.
2. Put `sdl-freerdp.exe` in the `freerdp` folder. Download the official
   64-bit static build from the
   [FreeRDP nightly CI](https://ci.freerdp.com/job/freerdp-nightly-windows/lastSuccessfulBuild/arch%3Dwin64%2Clabel%3Dvs2017/artifact/install/bin/sdl-freerdp.exe)
3. Open `PortableTailscaleRDP.exe`.
   PortableTailscale starts connecting immediately in the background. Complete
   browser sign-in if prompted; you can fill in the form while it connects.
4. Enter the tailnet computer, Windows username, optional domain, and password.
5. Move to **Connect** and press Enter.

### RDP controls

| Key | Action |
| --- | --- |
| Up / Down | Move between settings |
| Tab | Next tab (wraps to the first) |
| Enter | Move to the next setting; connect from the Connect row |
| Esc | Disconnect, or exit when disconnected |
| Ctrl+C | Exit |
| Ctrl+P | Browse and search saved profiles |
| Ctrl+S | Save or update the current connection profile |
| Ctrl+N | Clear the form for a new connection |
| Ctrl+L | Open diagnostics |
| F1 / F2 / F3 / F4 | Connection / Display / Sharing / Advanced tab |
| Ctrl+Left / Ctrl+Right | Previous / next tab |
| Left / Right or Space | Change the selected option |

### Settings tabs

- **Connection:** computer (including optional `host:port`), username, domain,
  and password.
- **Display:** fullscreen, initial resolution, dynamic desktop resizing, and
  desktop scaling. Initial resolution applies when FreeRDP launches; dynamic
  resizing subsequently follows the window size.
- **Sharing:** clipboard, remote audio, microphone, and a local folder path.
  Leave the folder blank to disable folder sharing. A selected folder appears
  in the remote session as `Shared`; it must exist on the current computer.
- **Advanced:** certificate policy, network preset, and connection timeout.
  `Ignore (legacy)` preserves the existing certificate behavior; `Verify / deny`
  rejects untrusted certificates without an interactive prompt.

Tab and Up/Down move within the current tab; Enter advances to Connect / Retry.
Each tab includes a Connect / Retry button. All options are saved with profiles;
profiles created before these tabs receive the existing defaults.

The launcher stays open when FreeRDP closes or a connection fails. Esc during a
connection disconnects and returns to the form; Ctrl+C disconnects and exits.
The Connect / Retry button reuses the current settings.

The Tailscale connection stays ready between RDP sessions. Connect reuses it,
or waits for startup to finish if necessary. Closing the launcher stops both
FreeRDP and its PortableTailscale process. If Tailscale fails to start or stops
unexpectedly, the next Connect attempt retries it.

Saved profiles contain the computer, username, domain, and every Display,
Sharing, and Advanced setting in `data/rdp-profiles.json` beside the launcher.
Passwords are never saved; loading a profile clears the password field. Ctrl+S
asks for a profile name, suggesting the computer name if you leave it blank.
Saving an existing profile name updates it; saving another name creates a
separate profile. In the profile browser, `/` searches, Enter loads, and
Backspace opens a deletion confirmation.

Diagnostics retain the latest 250 events in memory. Open them with Ctrl+L and
scroll with arrows or Page Up/Page Down. Ctrl+E exports the redacted events to a
timestamped `data/rdp-diagnostics-*.log` file. Passwords and URLs are redacted;
logs may still include computer names, usernames, IP addresses, and local paths.
FreeRDP warnings and errors are captured, and a running FreeRDP process is
reported separately from a successfully authenticated desktop session.

The layout adapts to terminal size, with a saved-computer sidebar on wide
terminals and a separate profile browser on smaller ones. The minimum supported
size is 44 columns by 18 rows; 80 by 24 or larger is recommended. Colors adapt
to light and dark terminal backgrounds.

Press `Ctrl+Alt+Enter` to leave a fullscreen FreeRDP session. `Alt+Tab` returns
to the launcher, where Esc disconnects the session.

## Build and releases

Builds and tests run in GitHub Actions. Every push to `main` and every pull
request runs the Windows workflow (`go vet`, `go test`, build, smoke test); the
Linux workflow runs race tests, short fuzz runs, and the real Chromium PAC test
under Xvfb.

Download the built executables from the **Actions** run artifacts. Tagging a
commit with `v*` publishes both executables as a GitHub Release.

The workflow builds with:

```powershell
go build -tags=ts_omit_logtail -trimpath -ldflags="-s -w" -o PortableTailscale.exe .\cmd\portabletailscale
go build -trimpath -ldflags="-s -w" -o PortableTailscaleRDP.exe .\cmd\tui
```

The RDP example also needs a Windows x64 build of `sdl-freerdp.exe`, available
from the
[FreeRDP nightly CI](https://ci.freerdp.com/job/freerdp-nightly-windows/lastSuccessfulBuild/arch%3Dwin64%2Clabel%3Dvs2017/artifact/install/bin/sdl-freerdp.exe)
([FreeRDP project](https://github.com/FreeRDP/FreeRDP)).

## Files

```text
PortableTailscale.exe
data/
  browser-proxy.json        # only after --install; prior PAC backup

# Optional RDP example
PortableTailscaleRDP.exe
freerdp/
  sdl-freerdp.exe
data/
  rdp-profiles.json
  rdp-diagnostics-*.log
```

The `data` folder holds the browser PAC backup and RDP profiles/diagnostics; no
Tailscale identity is stored. Delete any old `data/tailscaled.state` left by a
previous version. On NTFS, the folder and its files are restricted to the
current Windows user, SYSTEM and Administrators; removable FAT/exFAT media has
no ACLs, so there the folder is only as private as the drive.

## Options

```text
--install         Install the browser PAC and SSH config, then run
--uninstall       Remove the browser PAC and SSH config, then exit
--hostname NAME   Tailnet device name (default: portable-tailscale)
--json            Write newline-delimited status events
--no-browser      Print the sign-in URL without opening a browser
--state-dir PATH  Deprecated and ignored; no identity is persisted
```

`--json` events no longer include `stateDirectory`; consumers should ignore
removed or unknown fields.

## Acknowledgements

PortableTailscale is built on the following open-source projects:

| Project | Used for | License |
| --- | --- | --- |
| [Tailscale `tsnet`](https://pkg.go.dev/tailscale.com/tsnet) ([source](https://github.com/tailscale/tailscale/tree/main/tsnet)) | Userspace Tailscale node, MagicDNS dialing, and tailnet networking (`tailscale.com` v1.102.5) | BSD 3-Clause, see [licenses/LICENSE.Tailscale.txt](licenses/LICENSE.Tailscale.txt) |
| [Bubble Tea](https://github.com/charmbracelet/bubbletea), [Bubbles](https://github.com/charmbracelet/bubbles), and [Lip Gloss](https://github.com/charmbracelet/lipgloss) by Charm | Terminal UI of the RDP example | MIT, see [licenses/LICENSE.Charmbracelet.txt](licenses/LICENSE.Charmbracelet.txt) |
| [FreeRDP](https://github.com/FreeRDP/FreeRDP) `sdl-freerdp.exe` | RDP client started by the RDP example ([nightly build](https://ci.freerdp.com/job/freerdp-nightly-windows/)) | Apache 2.0, see [freerdp/LICENSE.FreeRDP.txt](freerdp/LICENSE.FreeRDP.txt) and [FREERDP.md](FREERDP.md) |
| [Playwright](https://playwright.dev/) | Chromium end-to-end test in CI | Apache 2.0 |

Tailscale is a trademark of Tailscale Inc. This project is not affiliated with
or endorsed by Tailscale Inc., Charmbracelet, Inc., or the FreeRDP project.
