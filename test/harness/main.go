// Command harness runs a private Tailscale world on loopback for end-to-end
// tests: a fake control server (tailscale.com/tstest/integration/testcontrol,
// which accepts any auth key), a DERP server, and one peer node serving HTTP
// over its tailnet address. The real PortableTailscale executable is driven
// against it — headless login, connected state, and proxied fetches through
// 127.0.0.1:41112 — with no secrets, so anyone can run the e2e suite.
//
// It prints key=value lines and then "ready", and keeps serving until it is
// killed (or 30 minutes pass).
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"tailscale.com/derp/derpserver"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

const (
	peerName    = "e2epeer"
	peerPort    = 8081
	peerPayload = "portabletailscale-e2e"
	authKey     = "e2e-key" // any non-empty key; testcontrol accepts all
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

func run() error {
	// Corp#4520: loopback test servers must not go through netns wrappers.
	netns.SetEnabled(false)

	controlURL, derpClose := startControl()
	defer derpClose()

	fqdn, peerClose, err := startPeer(controlURL)
	if err != nil {
		return err
	}
	defer peerClose()

	fmt.Printf("control=%s\n", controlURL)
	fmt.Printf("peer-short=%s\n", peerName)
	fmt.Printf("peer-fqdn=%s\n", fqdn)
	fmt.Printf("peer-port=%d\n", peerPort)
	fmt.Printf("payload=%s\n", peerPayload)
	fmt.Println("ready")

	// Serve until we are killed or the hard timeout passes; the e2e script
	// stops this process in its cleanup.
	time.Sleep(30 * time.Minute)
	return nil
}

// startControl runs the fake control plane plus its DERP server, both on
// loopback, mirroring tstest/integration.RunDERPAndSTUN without a testing.T.
func startControl() (controlURL string, closeAll func()) {
	d := derpserver.New(key.NewNode(), logger.Discard)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	handler := derpserver.AddWebSocketSupport(d, derpserver.Handler(d))
	httpsrv := httptest.NewUnstartedServer(handler)
	httpsrv.Listener.Close()
	httpsrv.Listener = ln
	httpsrv.Config.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
	httpsrv.StartTLS()

	derpPort := ln.Addr().(*net.TCPAddr).Port
	control := &testcontrol.Server{
		DERPMap: &tailcfg.DERPMap{
			Regions: map[int]*tailcfg.DERPRegion{
				1: {
					RegionID:   1,
					RegionCode: "e2e",
					Nodes: []*tailcfg.DERPNode{{
						Name:             "e2e1",
						RegionID:         1,
						HostName:         "127.0.0.1",
						IPv4:             "127.0.0.1",
						IPv6:             "none",
						STUNPort:         -1,
						DERPPort:         derpPort,
						InsecureForTests: true,
					}},
				},
			},
		},
		DNSConfig:       &tailcfg.DNSConfig{Proxied: true}, // MagicDNS on
		MagicDNSDomain:  "e2e-test.ts.net",
		Logf:            logger.Discard,
	}
	control.HTTPTestServer = httptest.NewUnstartedServer(control)
	control.HTTPTestServer.Start()

	return control.HTTPTestServer.URL, func() {
		control.HTTPTestServer.Close()
		httpsrv.CloseClientConnections()
		httpsrv.Close()
		d.Close()
		_ = ln.Close()
	}
}

// startPeer joins a second ephemeral node to the fake tailnet and serves
// peerPayload over HTTP on its tailnet address. Its listeners live inside
// tsnet's userspace network stack, so nothing is bound on the host.
func startPeer(controlURL string) (fqdn string, closeAll func(), err error) {
	dir, err := os.MkdirTemp("", "pt-e2e-peer")
	if err != nil {
		return "", nil, err
	}
	store, err := mem.New(logger.Discard, "")
	if err != nil {
		return "", nil, err
	}
	srv := &tsnet.Server{
		Dir:        dir,
		Store:      store,
		Hostname:   peerName,
		Ephemeral:  true,
		AuthKey:    authKey,
		ControlURL: controlURL,
		Logf:       logger.Discard,
	}
	if err := srv.Start(); err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := srv.Up(ctx); err != nil {
		srv.Close()
		return "", nil, fmt.Errorf("peer login: %w", err)
	}

	ln, err := srv.Listen("tcp", fmt.Sprintf(":%d", peerPort))
	if err != nil {
		srv.Close()
		return "", nil, err
	}
	go func() { _ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, peerPayload)
	})) }()

	lc, err := srv.LocalClient()
	if err != nil {
		srv.Close()
		return "", nil, err
	}
	status, err := lc.Status(ctx)
	if err != nil || status == nil || status.Self == nil {
		srv.Close()
		return "", nil, fmt.Errorf("peer status: %v", err)
	}
	fqdn = status.Self.DNSName
	return fqdn, func() { _ = ln.Close(); srv.Close() }, nil
}
