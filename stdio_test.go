package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func fakeConnectProxy(t *testing.T, allowed string) net.Listener {
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
				reader := bufio.NewReader(conn)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				fields := strings.Fields(line)
				if len(fields) < 2 {
					return
				}
				target := fields[1]
				if target != allowed {
					_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\nblocked")
					return
				}
				for {
					line, err := reader.ReadString('\n')
					if err != nil || line == "\r\n" || line == "\n" {
						break
					}
				}
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				_, _ = io.Copy(conn, reader)
			}()
		}
	}()
	return listener
}

func TestConnectViaProxy(t *testing.T) {
	proxy := fakeConnectProxy(t, "home-server:22")
	conn, reader, err := connectViaProxy(proxy.Addr().String(), "home-server:22")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

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

func TestConnectViaProxyRefused(t *testing.T) {
	proxy := fakeConnectProxy(t, "home-server:22")
	conn, _, err := connectViaProxy(proxy.Addr().String(), "example.com:443")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %v", err)
	}
}

func TestConnectViaProxyDown(t *testing.T) {
	_, _, err := connectViaProxy("127.0.0.1:1", "home-server:22")
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestStdioTarget(t *testing.T) {
	tests := []struct {
		args []string
		want string
		err  bool
	}{
		{[]string{"home-server"}, "home-server:22", false},
		{[]string{"home-server", "22"}, "home-server:22", false},
		{[]string{"home-server:2222"}, "home-server:2222", false},
		{[]string{"::1", "22"}, "[::1]:22", false},
		{[]string{"home-server", "abc"}, "", true},
		{nil, "", true},
		{[]string{"a", "22", "extra"}, "", true},
	}
	for _, tt := range tests {
		got, err := stdioTarget(tt.args)
		if tt.err {
			if err == nil {
				t.Errorf("stdioTarget(%v) = %q, want error", tt.args, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("stdioTarget(%v): %v", tt.args, err)
			continue
		}
		if got != tt.want {
			t.Errorf("stdioTarget(%v) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestFakeProxyTarget(t *testing.T) {
	// Guards the test helper itself against a silent regression.
	proxy := fakeConnectProxy(t, "home-server:22")
	conn, err := net.Dial("tcp", proxy.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT home-server:22 HTTP/1.1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("status = %q", line)
	}
}
