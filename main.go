// PortableTailscale exposes an embedded, ephemeral Tailscale node as a
// loopback SOCKS5 proxy plus an automatic browser/SSH path to the tailnet.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"portabletailscale/internal/private"

	"tailscale.com/ipn/store/mem"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

var authURLPattern = regexp.MustCompile(`https://login\.tailscale\.com/a/[A-Za-z0-9_-]+`)

type options struct {
	hostname  string
	json      bool
	noBrowser bool
	install   bool
	uninstall bool
	stdio     bool
}

type event struct {
	Event       string `json:"event"`
	Message     string `json:"message,omitempty"`
	AuthURL     string `json:"authUrl,omitempty"`
	ProxyURL    string `json:"proxyUrl,omitempty"`
	ProxyAddr   string `json:"proxyAddress,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	TailscaleIP string `json:"tailscaleIp,omitempty"`
	HTTPProxy   string `json:"httpProxy,omitempty"`
	PACURL      string `json:"pacUrl,omitempty"`
}

type reporter struct {
	json  bool
	color bool
	mu    sync.Mutex
}

func (r *reporter) emit(e event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.json {
		_ = json.NewEncoder(os.Stdout).Encode(e)
		return
	}

	switch e.Event {
	case "starting":
		fmt.Println(header(r.color))
		fmt.Println()
		fmt.Println("Starting Portable Tailscale (ephemeral session)")
	case "auth":
		fmt.Printf("Authenticate this device:\n%s\n", e.AuthURL)
	case "connected":
		fmt.Printf("\nTailscale connected (%s)\n", e.TailscaleIP)
		fmt.Printf("SOCKS5 address: %s\n", e.ProxyAddr)
		fmt.Printf("Username:       %s\n", e.Username)
		fmt.Printf("Password:       %s\n", e.Password)
		fmt.Printf("Proxy URL:      %s\n", e.ProxyURL)
		if e.HTTPProxy != "" {
			fmt.Printf("HTTP proxy:     %s\n", e.HTTPProxy)
			fmt.Printf("PAC file:       %s\n", e.PACURL)
		}
		fmt.Println("\nKeep this window open while the proxy is in use. Press Ctrl+C to stop.")
	case "message":
		fmt.Println(e.Message)
	case "stopping":
		fmt.Println("\nStopping proxy...")
	case "error":
		fmt.Fprintf(os.Stderr, "Error: %s\n", e.Message)
	}
}

// header draws the Tailscale logo (a 3x3 dot grid with the middle row and
// bottom centre lit) beside the product name. Colours use ANSI escapes only
// when color is true.
func header(color bool) string {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	on := paint("38;5;255", "●")
	off := paint("38;5;240", "●")
	return strings.Join([]string{
		off + " " + off + " " + off,
		on + " " + on + " " + on + "    " + paint("1;38;5;63", "Portable Tailscale"),
		off + " " + on + " " + off,
	}, "\n")
}

func main() {
	opts, err := parseOptions()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	switch {
	case opts.uninstall:
		os.Exit(uninstall())
	case opts.stdio:
		os.Exit(runStdio(flag.Args()))
	default:
		os.Exit(run(opts))
	}
}

func run(opts options) int {
	report := &reporter{json: opts.json, color: !opts.json && enableColor()}
	report.emit(event{Event: "starting"})

	cleanupStaleRuntimeDirs(os.TempDir(), runtimeDirMaxAge, time.Now())
	runtimeDir, err := os.MkdirTemp("", runtimeDirPrefix)
	if err != nil {
		report.emit(event{Event: "error", Message: fmt.Sprintf("create temporary runtime directory: %v", err)})
		return 1
	}
	defer os.RemoveAll(runtimeDir)
	// The temp directory holds tsnet logs and ephemeral state; keep it private
	// on NTFS. FAT/exFAT has no ACLs, so this is best effort.
	if err := private.Dir(runtimeDir); err != nil {
		fmt.Fprintf(os.Stderr, "warning: cannot restrict runtime directory permissions: %v\n", err)
	}

	stateStore, err := mem.New(logger.Discard, "")
	if err != nil {
		report.emit(event{Event: "error", Message: fmt.Sprintf("create in-memory state store: %v", err)})
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var browserOnce sync.Once
	userLogf := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		authURL := authURLPattern.FindString(message)
		if authURL == "" {
			return
		}

		browserOnce.Do(func() {
			report.emit(event{Event: "auth", AuthURL: authURL})
			if !opts.noBrowser {
				if err := openBrowser(authURL); err != nil {
					report.emit(event{Event: "error", Message: fmt.Sprintf("open browser: %v", err)})
				}
			}
		})
	}

	srv := &tsnet.Server{
		Dir:       runtimeDir,
		Store:     stateStore,
		Hostname:  opts.hostname,
		Ephemeral: true,
		UserLogf:  userLogf,
		Logf:      logger.Discard,
	}

	dataDir, dataErr := executableDataDir()
	sshPath, sshErr := sshConfigPath()
	needHTTPProxy := opts.install ||
		(dataErr == nil && browserConfigured(dataDir)) ||
		(sshErr == nil && hasSSHBlock(sshPath))

	var proxy *localProxy
	var proxyListener net.Listener
	var httpServer *http.Server
	if needHTTPProxy {
		// Bind before login so a busy port fails fast instead of after an
		// interactive sign-in.
		proxyListener, err = net.Listen("tcp", localProxyAddr)
		if err != nil {
			report.emit(event{Event: "error", Message: fmt.Sprintf("start local proxy on %s: %v (is another instance running?)", localProxyAddr, err)})
			return 1
		}
		proxy = newLocalProxy(srv)
		httpServer = &http.Server{
			Handler:           proxy,
			ReadHeaderTimeout: 15 * time.Second,
		}
		go func() { _ = httpServer.Serve(proxyListener) }()
		defer func() {
			_ = httpServer.Close()
			_ = proxyListener.Close()
		}()
	}

	if err := srv.Start(); err != nil {
		report.emit(event{Event: "error", Message: fmt.Sprintf("start Tailscale: %v", err)})
		return 1
	}
	defer srv.Close()

	status, err := srv.Up(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		report.emit(event{Event: "error", Message: fmt.Sprintf("connect to Tailscale: %v", err)})
		return 1
	}

	addr, proxyPassword, _, err := srv.Loopback()
	if err != nil {
		report.emit(event{Event: "error", Message: fmt.Sprintf("start SOCKS5 proxy: %v", err)})
		return 1
	}

	proxyURL := (&url.URL{
		Scheme: "socks5",
		User:   url.UserPassword("tsnet", proxyPassword),
		Host:   addr,
	}).String()

	tailscaleIP := "unknown"
	if status != nil && len(status.TailscaleIPs) > 0 {
		tailscaleIP = status.TailscaleIPs[0].String()
	} else if ip4, ip6 := srv.TailscaleIPs(); ip4.IsValid() {
		tailscaleIP = ip4.String()
	} else if ip6.IsValid() {
		tailscaleIP = ip6.String()
	}

	pacURL := pacURLFor(time.Now())
	peers := peerList{}
	if proxy != nil {
		proxy.cache.reset()
		peers = proxy.peers(ctx)
	}
	exePath, exeErr := os.Executable()
	if exeErr == nil {
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
	}

	if opts.install {
		installBrowser(report, dataDir, dataErr, pacURL)
		installSSH(report, sshPath, sshErr, exePath, exeErr, peers)
	} else {
		refreshInstalled(report, dataDir, pacURL, sshPath, exePath, peers)
	}

	connected := event{
		Event:       "connected",
		ProxyURL:    proxyURL,
		ProxyAddr:   addr,
		Username:    "tsnet",
		Password:    proxyPassword,
		TailscaleIP: tailscaleIP,
	}
	if needHTTPProxy {
		connected.HTTPProxy = "http://" + localProxyAddr
		connected.PACURL = pacURL
	}
	report.emit(connected)

	<-ctx.Done()
	report.emit(event{Event: "stopping"})
	return 0
}

func installBrowser(report *reporter, dataDir string, dataErr error, pacURL string) {
	if dataErr != nil {
		report.emit(event{Event: "message", Message: "Browser setup skipped: " + dataErr.Error()})
		return
	}
	if err := installBrowserPAC(dataDir, pacURL); err != nil {
		report.emit(event{Event: "message", Message: "Browser setup failed: " + err.Error()})
		return
	}
	report.emit(event{Event: "message", Message: "Browser proxy configured. Restart Chrome or Edge once so it reads the PAC file."})
}

func installSSH(report *reporter, sshPath string, sshErr error, exePath string, exeErr error, peers peerList) {
	if sshErr != nil {
		report.emit(event{Event: "message", Message: "SSH setup skipped: " + sshErr.Error()})
		return
	}
	if exeErr != nil {
		report.emit(event{Event: "message", Message: "SSH setup skipped: " + exeErr.Error()})
		return
	}
	if err := installSSHConfig(sshPath, exePath, peers); err != nil {
		report.emit(event{Event: "message", Message: "SSH setup failed: " + err.Error()})
		return
	}
	report.emit(event{Event: "message", Message: "SSH configured for " + sshHostList(peers)})
}

func refreshInstalled(report *reporter, dataDir, pacURL, sshPath, exePath string, peers peerList) {
	if dataDir != "" && browserConfigured(dataDir) {
		if err := refreshBrowserPAC(dataDir, pacURL); err != nil {
			report.emit(event{Event: "message", Message: "Browser refresh failed: " + err.Error()})
		}
	}
	if sshPath != "" && exePath != "" && hasSSHBlock(sshPath) {
		if err := upsertSSHConfig(sshPath, renderSSHBlock(exePath, peers)); err != nil {
			report.emit(event{Event: "message", Message: "SSH refresh failed: " + err.Error()})
		}
	}
}

func uninstall() int {
	code := 0
	dataDir, err := executableDataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "PortableTailscale:", err)
		code = 1
	} else if err := uninstallBrowserPAC(dataDir); err != nil {
		fmt.Fprintln(os.Stderr, "PortableTailscale: browser:", err)
		code = 1
	}

	path, err := sshConfigPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "PortableTailscale:", err)
		code = 1
	} else if err := removeSSHConfig(path); err != nil {
		fmt.Fprintln(os.Stderr, "PortableTailscale: ssh:", err)
		code = 1
	}
	return code
}

func parseOptions() (options, error) {
	var opts options
	flag.StringVar(&opts.hostname, "hostname", "portable-tailscale", "device name shown in the Tailscale admin console")
	flag.BoolVar(&opts.json, "json", false, "write newline-delimited JSON events")
	flag.BoolVar(&opts.noBrowser, "no-browser", false, "print the authentication URL without opening it")
	flag.BoolVar(&opts.install, "install", false, "install the browser PAC and SSH config, then run")
	flag.BoolVar(&opts.uninstall, "uninstall", false, "remove the browser PAC and SSH config, then exit")
	flag.BoolVar(&opts.stdio, "stdio", false, "internal: tunnel stdin/stdout to HOST PORT")
	flag.Parse()

	if opts.install && opts.uninstall {
		return options{}, errors.New("--install and --uninstall are mutually exclusive")
	}
	return opts, nil
}

func executableDirectory() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find executable directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return filepath.Dir(resolved), nil
}

func executableDataDir() (string, error) {
	dir, err := executableDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "data"), nil
}

func openBrowser(address string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("automatic browser launch is only supported on Windows")
	}
	cmd := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() {
		_ = cmd.Wait()
	}()
	return nil
}
