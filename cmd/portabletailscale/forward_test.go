package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseForwards(t *testing.T) {
	got, err := parseForwards([]string{"3080:3080", "22:2222"})
	if err != nil {
		t.Fatal(err)
	}
	want := []forwardSpec{{TailnetPort: 3080, LocalPort: 3080}, {TailnetPort: 22, LocalPort: 2222}}
	if len(got) != len(want) {
		t.Fatalf("parsed %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parsed %+v, want %+v", got, want)
		}
	}

	for _, bad := range []string{"3080", "3080:", ":3080", "a:b", "0:1", "1:99999", "3080:3080:3080", "-1:80"} {
		if _, err := parseForwards([]string{bad}); err == nil {
			t.Errorf("parseForwards(%q) accepted an invalid spec", bad)
		}
	}
	if got, err := parseForwards(nil); err != nil || len(got) != 0 {
		t.Errorf("parseForwards(nil) = %+v, %v; want empty", got, err)
	}
}

func TestServeForwardRelays(t *testing.T) {
	// The local side of the bridge: an HTTP server on loopback.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bridge-ok:" + r.Host))
	}))
	defer server.Close()
	serverPort := server.Listener.Addr().(*net.TCPAddr).Port

	// The "tailnet" side: a loopback listener standing in for the node's
	// in-tunnel netstack listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveForward(ln, serverPort)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// One request/response pair through the relay, like a browser hit. The
	// Host header must arrive unmodified: DSH's /api fence keys on it.
	request, err := http.NewRequest(http.MethodGet, "http://dsh-host:3080/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Connection", "close")
	if err := request.Write(client); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("relay response status = %d", response.StatusCode)
	}
	if string(body) != "bridge-ok:dsh-host:3080" {
		t.Fatalf("relay did not preserve the request (Host header): %q", body)
	}
}
