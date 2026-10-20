package main

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestBuildPeerListNormalizesAndSorts(t *testing.T) {
	peers := []peerHost{
		{HostName: "Home-Server", DNSName: "home-server.tail.ts.net.", IPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
		{HostName: "home-server", IPs: []netip.Addr{netip.MustParseAddr("100.64.0.2")}},
		{HostName: "", DNSName: "", IPs: []netip.Addr{netip.MustParseAddr("fd7a:115c:a1e0::1")}},
	}
	list := buildPeerList(peers)

	wantNames := []string{"home-server", "home-server.tail.ts.net"}
	if len(list.Names) != len(wantNames) {
		t.Fatalf("names = %v, want %v", list.Names, wantNames)
	}
	for i, name := range wantNames {
		if list.Names[i] != name {
			t.Errorf("names[%d] = %q, want %q", i, list.Names[i], name)
		}
	}
	if len(list.IPs) != 3 || list.IPs[0] != "100.64.0.2" {
		t.Errorf("ips = %v", list.IPs)
	}
	bracketed := false
	for _, ip := range list.IPs {
		if ip == "[fd7a:115c:a1e0::1]" {
			bracketed = true
		}
	}
	if !bracketed {
		t.Errorf("missing bracketed IPv6 entry: %v", list.IPs)
	}
}

func TestProxyAllowedTargets(t *testing.T) {
	proxy := &localProxy{peersFn: func(context.Context) peerList {
		return peerList{Names: []string{"home-server", "home-server.tail.ts.net"}}
	}}

	allowed := []string{"home-server", "HOME-SERVER", "home-server.tail.ts.net", "anything.ts.net", "100.64.0.1", "fd7a:115c:a1e0::1"}
	for _, host := range allowed {
		host = normalizeTestHost(host)
		if !proxy.allowed(context.Background(), host) {
			t.Errorf("expected %q to be allowed", host)
		}
	}

	blocked := []string{"example.com", "8.8.8.8", "127.0.0.1", "localhost", "home-server.example.com", "ts.net"}
	for _, host := range blocked {
		host = normalizeTestHost(host)
		if proxy.allowed(context.Background(), host) {
			t.Errorf("expected %q to be blocked", host)
		}
	}
}

func normalizeTestHost(host string) string {
	h, _, err := splitTarget(host, "443")
	if err != nil {
		return host
	}
	return h
}

func TestPeerCacheTTL(t *testing.T) {
	calls := 0
	cache := &peerCache{ttl: 50 * time.Millisecond}
	fetch := func(context.Context) peerList {
		calls++
		return peerList{Names: []string{"home-server"}}
	}

	cache.get(context.Background(), fetch)
	cache.get(context.Background(), fetch)
	if calls != 1 {
		t.Fatalf("cache calls = %d, want 1", calls)
	}

	time.Sleep(80 * time.Millisecond)
	cache.get(context.Background(), fetch)
	if calls != 2 {
		t.Fatalf("cache calls = %d, want 2", calls)
	}
}

func TestSplitTarget(t *testing.T) {
	tests := []struct {
		in, def        string
		host, port     string
		wantErr        bool
	}{
		{"home-server", "443", "home-server", "443", false},
		{"home-server:8080", "443", "home-server", "8080", false},
		{"HOME-SERVER:22", "443", "home-server", "22", false},
		{"home-server.", "443", "home-server", "443", false},
		{"[::1]:443", "80", "::1", "443", false},
		{"::1", "443", "::1", "443", false},
		{"", "443", "", "", true},
		{"home-server:0", "443", "", "", true},
		{"home-server:99999", "443", "", "", true},
		{"home-server:abc", "443", "", "", true},
		{"bad host:80", "443", "", "", true},
		{"http://home-server", "443", "", "", true},
	}

	for _, tt := range tests {
		host, port, err := splitTarget(tt.in, tt.def)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitTarget(%q) = %q, %q, want error", tt.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitTarget(%q): %v", tt.in, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("splitTarget(%q) = %q, %q; want %q, %q", tt.in, host, port, tt.host, tt.port)
		}
	}
}
