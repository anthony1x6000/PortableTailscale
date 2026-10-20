package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func testProxy(t *testing.T, dial func(context.Context, string, string) (net.Conn, error), peers peerList) *httptest.Server {
	t.Helper()
	proxy := &localProxy{
		dial:    dial,
		peersFn: func(context.Context) peerList { return peers },
	}
	proxy.tr = proxy.newTransport()
	proxy.pacToken = "test-token"
	server := httptest.NewServer(proxy)
	proxy.pacAddr = server.Listener.Addr().String()
	t.Cleanup(server.Close)
	return server
}

func rawConnect(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(status)
	if len(fields) < 2 {
		t.Fatalf("bad status line %q", status)
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("bad status line %q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, reader, code
}

func echoListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener
}

func TestProxyConnectEcho(t *testing.T) {
	echo := echoListener(t)
	dial := func(context.Context, string, string) (net.Conn, error) {
		return net.Dial("tcp", echo.Addr().String())
	}
	server := testProxy(t, dial, peerList{Names: []string{"home-server"}})

	conn, reader, code := rawConnect(t, server.Listener.Addr().String(), "home-server:22")
	defer conn.Close()
	if code != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", code)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
}

func TestProxyRejectsForeignTarget(t *testing.T) {
	var dialed atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialed.Add(1)
		return nil, fmt.Errorf("unexpected dial")
	}
	server := testProxy(t, dial, peerList{Names: []string{"home-server"}})

	conn, _, code := rawConnect(t, server.Listener.Addr().String(), "example.com:443")
	_ = conn.Close()
	if code != http.StatusForbidden {
		t.Fatalf("CONNECT status = %d, want 403", code)
	}
	if dialed.Load() != 0 {
		t.Fatalf("dialed a blocked target")
	}
}

func TestProxyDefaultConnectPort(t *testing.T) {
	dialed := make(chan string, 1)
	dial := func(_ context.Context, _ string, addr string) (net.Conn, error) {
		dialed <- addr
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	server := testProxy(t, dial, peerList{Names: []string{"home-server"}})

	conn, _, code := rawConnect(t, server.Listener.Addr().String(), "home-server")
	_ = conn.Close()
	if code != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", code)
	}
	select {
	case addr := <-dialed:
		if addr != "home-server:443" {
			t.Fatalf("dialed %q, want home-server:443", addr)
		}
	default:
		t.Fatal("no dial observed")
	}
}

func TestProxyForward(t *testing.T) {
	var mu sync.Mutex
	var host string
	var removed string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		host = r.Host
		removed = r.Header.Get("X-Remove")
		mu.Unlock()
		_, _ = io.WriteString(w, "hello-through-proxy")
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	_, port, _ := net.SplitHostPort(upstreamURL.Host)
	dial := func(_ context.Context, _ string, addr string) (net.Conn, error) {
		if addr != "home-server:"+port {
			return nil, fmt.Errorf("unexpected dial %q", addr)
		}
		return net.Dial("tcp", upstream.Listener.Addr().String())
	}
	server := testProxy(t, dial, peerList{Names: []string{"home-server"}})

	proxyURL, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, err := http.NewRequest(http.MethodGet, "http://home-server:"+port+"/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "X-Remove")
	req.Header.Set("X-Remove", "secret")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "hello-through-proxy" {
		t.Fatalf("response = %d %q", resp.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if host != "home-server:"+port {
		t.Fatalf("upstream Host = %q", host)
	}
	if removed != "" {
		t.Fatalf("hop-by-hop header leaked: %q", removed)
	}
}

func TestProxyForwardRejected(t *testing.T) {
	server := testProxy(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("unexpected dial")
	}, peerList{Names: []string{"home-server"}})

	proxyURL, _ := url.Parse(server.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxyOriginFormRejected(t *testing.T) {
	server := testProxy(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("unexpected dial")
	}, peerList{Names: []string{"home-server"}})

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestProxyDialFailure(t *testing.T) {
	server := testProxy(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("dial failed")
	}, peerList{Names: []string{"home-server"}})

	conn, _, code := rawConnect(t, server.Listener.Addr().String(), "home-server:22")
	_ = conn.Close()
	if code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", code)
	}
}

func TestProxyPAC(t *testing.T) {
	server := testProxy(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("unexpected dial")
	}, peerList{Names: []string{"home-server"}, IPs: []string{"100.64.0.1"}})

	resp, err := http.Get(server.URL + pacPath + "?t=test-token")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)
	proxyAddr := server.Listener.Addr().String()
	for _, want := range []string{"FindProxyForURL", `"home-server"`, `"100.64.0.1"`, "PROXY " + proxyAddr, "DIRECT"} {
		if !strings.Contains(text, want) {
			t.Errorf("PAC missing %q:\n%s", want, text)
		}
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-ns-proxy-autoconfig" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestProxyPACRejectsMissingToken(t *testing.T) {
	server := testProxy(t, func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("unexpected dial")
	}, peerList{Names: []string{"home-server"}})

	resp, err := http.Get(server.URL + pacPath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestProxyConcurrentConnect(t *testing.T) {
	echo := echoListener(t)
	dial := func(context.Context, string, string) (net.Conn, error) {
		return net.Dial("tcp", echo.Addr().String())
	}
	server := testProxy(t, dial, peerList{Names: []string{"home-server"}})

	done := make(chan error, 5)
	for i := 0; i < 5; i++ {
		go func() {
			conn, reader, code := rawConnectNoFail(t, server.Listener.Addr().String(), "home-server:22")
			if code != http.StatusOK {
				done <- fmt.Errorf("status %d", code)
				return
			}
			defer conn.Close()
			_, _ = conn.Write([]byte("x"))
			buf := make([]byte, 1)
			_, err := io.ReadFull(reader, buf)
			done <- err
		}()
	}
	for i := 0; i < 5; i++ {
		if err := <-done; err != nil {
			t.Error(err)
		}
	}
}

func rawConnectNoFail(t *testing.T, proxyAddr, target string) (net.Conn, *bufio.Reader, int) {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Error(err)
		return nil, nil, 0
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Error(err)
		return conn, nil, 0
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Error(err)
		return conn, reader, 0
	}
	fields := strings.Fields(status)
	code, _ := strconv.Atoi(fields[1])
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Error(err)
			return conn, reader, code
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, reader, code
}
