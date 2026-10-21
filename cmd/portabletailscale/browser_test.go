package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

type browserTestConfig struct {
	PACURL    string `json:"pacUrl"`
	HTTPURL   string `json:"httpUrl"`
	HTTPSURL  string `json:"httpsUrl"`
	DirectURL string `json:"directUrl"`
}

// TestChromiumBrowser runs a real Chromium through the generated PAC file.
// It is skipped unless BROWSER_TEST=1; CI runs it under Xvfb.
func TestChromiumBrowser(t *testing.T) {
	if os.Getenv("BROWSER_TEST") != "1" {
		t.Skip("set BROWSER_TEST=1 to run the Playwright browser test")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node is required for the browser test")
	}

	var mu sync.Mutex
	var hosts []string
	record := func(w http.ResponseWriter, r *http.Request, body string) {
		mu.Lock()
		hosts = append(hosts, r.Host)
		mu.Unlock()
		_, _ = w.Write([]byte(body))
	}

	httpUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(w, r, "proxied-http")
	}))
	defer httpUpstream.Close()

	tlsUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(w, r, "proxied-https")
	}))
	defer tlsUpstream.Close()

	directUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	defer directUpstream.Close()

	httpPort := httpUpstream.Listener.Addr().(*net.TCPAddr).Port
	tlsPort := tlsUpstream.Listener.Addr().(*net.TCPAddr).Port
	directPort := directUpstream.Listener.Addr().(*net.TCPAddr).Port

	dial := func(_ context.Context, _ string, addr string) (net.Conn, error) {
		switch addr {
		case fmt.Sprintf("home-server:%d", httpPort):
			return net.Dial("tcp", httpUpstream.Listener.Addr().String())
		case fmt.Sprintf("home-server:%d", tlsPort):
			return net.Dial("tcp", tlsUpstream.Listener.Addr().String())
		}
		return nil, fmt.Errorf("unexpected proxy dial %q", addr)
	}
	proxy := &localProxy{
		dial:    dial,
		peersFn: func(context.Context) peerList { return peerList{Names: []string{"home-server"}} },
	}
	proxy.tr = proxy.newTransport()
	proxy.pacToken = "browser-token"
	server := httptest.NewServer(proxy)
	proxy.pacAddr = server.Listener.Addr().String()
	defer server.Close()

	config := browserTestConfig{
		PACURL:    server.URL + pacPath + "?t=browser-token",
		HTTPURL:   fmt.Sprintf("http://home-server:%d/", httpPort),
		HTTPSURL:  fmt.Sprintf("https://home-server:%d/", tlsPort),
		DirectURL: fmt.Sprintf("http://direct.test:%d/", directPort),
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "browser.json")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(node, filepath.Join("..", "..", "test", "browser.mjs"), configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("chromium browser test failed: %v\n%s", err, output)
	}

	mu.Lock()
	got := append([]string(nil), hosts...)
	mu.Unlock()
	for _, want := range []string{
		fmt.Sprintf("home-server:%d", httpPort),
		fmt.Sprintf("home-server:%d", tlsPort),
	} {
		found := false
		for _, host := range got {
			if host == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("upstream never saw Host %q (saw %v)", want, got)
		}
	}
}
