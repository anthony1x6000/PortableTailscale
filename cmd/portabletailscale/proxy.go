package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tailscale.com/tsnet"
)

const (
	localProxyAddr = "127.0.0.1:41112"
	pacPath        = "/proxy.pac"
	peerCacheTTL   = 5 * time.Second
)

var errTargetNotTailnet = errors.New("target is not on the tailnet")

// Peer hostnames become SSH Host patterns, so allow only DNS-label characters.
var peerNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,252}$`)

func validPeerName(name string) bool {
	return peerNamePattern.MatchString(name) && !strings.Contains(name, "..")
}

func pacBaseURL() string {
	return "http://" + localProxyAddr + pacPath
}

func pacURLFor(token string, now time.Time) string {
	return fmt.Sprintf("%s?t=%s&v=%d", pacBaseURL(), token, now.UnixNano())
}

// randRead is a seam so tests can simulate an unavailable crypto source.
var randRead = rand.Read

// newPACtoken mints the per-run PAC bearer token. The token gates peer-list
// disclosure, so a crypto-source failure is fatal rather than degraded to a
// guessable value (crypto/rand itself crashes rather than erroring on all
// toolchains this module supports; the explicit panic keeps that contract
// even if randRead is ever swapped).
func newPACtoken() string {
	var buf [16]byte
	n, err := randRead(buf[:])
	if err == nil && n != len(buf) {
		err = fmt.Errorf("short read: %d of %d bytes", n, len(buf))
	}
	if err != nil {
		panic("PortableTailscale: crypto source unavailable for PAC token: " + err.Error())
	}
	return hex.EncodeToString(buf[:])
}

type peerHost struct {
	HostName string
	DNSName  string
	IPs      []netip.Addr
}

type peerList struct {
	Names []string
	IPs   []string
}

func (l peerList) hasName(host string) bool {
	for _, name := range l.Names {
		if name == host {
			return true
		}
	}
	return false
}

func (l peerList) hasIP(host string) bool {
	for _, ip := range l.IPs {
		if ip == host {
			return true
		}
	}
	return false
}

func buildPeerList(peers []peerHost) peerList {
	names := make(map[string]struct{})
	ips := make(map[string]struct{})
	for _, peer := range peers {
		for _, name := range []string{peer.HostName, peer.DNSName} {
			name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
			if validPeerName(name) {
				names[name] = struct{}{}
			}
		}
		for _, ip := range peer.IPs {
			if !ip.IsValid() {
				continue
			}
			ips[ip.String()] = struct{}{}
			if ip.Is6() {
				// PAC receives IPv6 literals in brackets.
				ips["["+ip.String()+"]"] = struct{}{}
			}
		}
	}

	list := peerList{}
	for name := range names {
		list.Names = append(list.Names, name)
	}
	for ip := range ips {
		list.IPs = append(list.IPs, ip)
	}
	sort.Strings(list.Names)
	sort.Strings(list.IPs)
	return list
}

type peerCache struct {
	mu   sync.Mutex
	at   time.Time
	list peerList
	ttl  time.Duration
}

func (c *peerCache) reset() {
	c.mu.Lock()
	c.at = time.Time{}
	c.list = peerList{}
	c.mu.Unlock()
}

func (c *peerCache) get(ctx context.Context, fetch func(context.Context) peerList) peerList {
	ttl := c.ttl
	if ttl <= 0 {
		ttl = peerCacheTTL
	}

	c.mu.Lock()
	if !c.at.IsZero() && time.Since(c.at) < ttl {
		list := c.list
		c.mu.Unlock()
		return list
	}
	c.mu.Unlock()

	// Do not hold the lock across the status call: a slow refresh must not
	// block every proxied request.
	list := fetch(ctx)

	c.mu.Lock()
	c.list = list
	c.at = time.Now()
	c.mu.Unlock()
	return list
}

type localProxy struct {
	srv     *tsnet.Server
	dial    func(context.Context, string, string) (net.Conn, error)
	peersFn func(context.Context) peerList
	pacAddr string
	pacToken string
	tr      *http.Transport
	cache   peerCache
}

func newLocalProxy(srv *tsnet.Server) *localProxy {
	p := &localProxy{srv: srv, dial: srv.Dial, pacAddr: localProxyAddr, pacToken: newPACtoken()}
	p.peersFn = p.fetchPeers
	p.tr = p.newTransport()
	return p
}

func (p *localProxy) newTransport() *http.Transport {
	return &http.Transport{
		Proxy:              nil,
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		MaxIdleConns:       32,
		IdleConnTimeout:    90 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return p.dialTarget(ctx, network, addr)
		},
	}
}

func (p *localProxy) transport() *http.Transport {
	return p.tr
}

func (p *localProxy) peers(ctx context.Context) peerList {
	if p.peersFn == nil {
		return peerList{}
	}
	return p.cache.get(ctx, p.peersFn)
}

func (p *localProxy) fetchPeers(ctx context.Context) peerList {
	if p.srv == nil {
		return peerList{}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	lc, err := p.srv.LocalClient()
	if err != nil {
		return peerList{}
	}
	status, err := lc.Status(ctx)
	if err != nil || status == nil {
		return peerList{}
	}

	peers := make([]peerHost, 0, len(status.Peer))
	for _, peer := range status.Peer {
		if peer == nil {
			continue
		}
		peers = append(peers, peerHost{
			HostName: peer.HostName,
			DNSName:  peer.DNSName,
			IPs:      peer.TailscaleIPs,
		})
	}
	return buildPeerList(peers)
}

func (p *localProxy) allowed(ctx context.Context, host string) bool {
	peers := p.peers(ctx)
	if _, err := netip.ParseAddr(host); err == nil {
		return peers.hasIP(host)
	}
	return peers.hasName(host)
}

func (p *localProxy) dialTarget(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := splitTarget(addr, "80")
	if err != nil {
		return nil, err
	}
	if !p.allowed(ctx, host) {
		return nil, errTargetNotTailnet
	}
	return p.dial(ctx, network, net.JoinHostPort(host, port))
}

func (p *localProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == pacPath {
		if p.pacToken != "" && r.URL.Query().Get("t") != p.pacToken {
			http.Error(w, "invalid PAC token", http.StatusForbidden)
			return
		}
		addr := p.pacAddr
		if addr == "" {
			addr = localProxyAddr
		}
		body := buildPAC(addr, p.peers(r.Context()))
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_, _ = io.WriteString(w, body)
		return
	}
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if r.URL.Host == "" {
		http.Error(w, "absolute-form request required", http.StatusBadRequest)
		return
	}
	p.handleForward(w, r)
}

func (p *localProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := splitTarget(r.Host, "443")
	if err != nil {
		http.Error(w, "invalid CONNECT target", http.StatusBadRequest)
		return
	}
	if !p.allowed(r.Context(), host) {
		http.Error(w, "target is not on the tailnet", http.StatusForbidden)
		return
	}
	target := net.JoinHostPort(host, port)

	dialCtx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	upstream, err := p.dial(dialCtx, "tcp", target)
	if err != nil {
		http.Error(w, "tailnet dial failed", http.StatusBadGateway)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	_ = client.SetDeadline(time.Time{})
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, buf.Reader)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
	_ = client.Close()
	_ = upstream.Close()
}

func (p *localProxy) handleForward(w http.ResponseWriter, r *http.Request) {
	host, _, err := splitTarget(r.URL.Host, "80")
	if err != nil {
		http.Error(w, "invalid proxy target", http.StatusBadRequest)
		return
	}
	if !p.allowed(r.Context(), host) {
		http.Error(w, "target is not on the tailnet", http.StatusForbidden)
		return
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	out.Header = r.Header.Clone()
	removeHopHeaders(out.Header)
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	out.Close = false

	resp, err := p.transport().RoundTrip(out)
	if err != nil {
		http.Error(w, "tailnet request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func buildPAC(proxyAddr string, peers peerList) string {
	hosts := append([]string{}, peers.Names...)
	hosts = append(hosts, peers.IPs...)
	sort.Strings(hosts)
	raw, err := json.Marshal(hosts)
	if err != nil {
		raw = []byte("[]")
	}
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  var hosts = %s;
  for (var i = 0; i < hosts.length; i++) {
    if (host === hosts[i]) return "PROXY %s";
  }
  return "DIRECT";
}
`, raw, proxyAddr)
}

func splitTarget(addr, defaultPort string) (host, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", errors.New("empty target")
	}

	if h, p, splitErr := net.SplitHostPort(addr); splitErr == nil {
		host, port = h, p
	} else if strings.Count(addr, ":") > 1 {
		ip, parseErr := netip.ParseAddr(strings.Trim(addr, "[]"))
		if parseErr != nil {
			return "", "", fmt.Errorf("invalid target %q", addr)
		}
		host, port = ip.String(), defaultPort
	} else {
		host, port = addr, defaultPort
	}

	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, " \t\r\n/\\@?#\"") {
		return "", "", fmt.Errorf("invalid host %q", host)
	}
	if port == "" {
		port = defaultPort
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", "", fmt.Errorf("invalid port %q", port)
	}
	return host, port, nil
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(header http.Header) {
	for _, field := range strings.Split(header.Get("Connection"), ",") {
		if field = strings.TrimSpace(field); field != "" {
			header.Del(field)
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func closeWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}
