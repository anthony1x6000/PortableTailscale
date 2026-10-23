package main

import (
	"strings"
	"testing"
)

func TestUsageExamples(t *testing.T) {
	withProxy := usageExamples(true, "socks5h://tsnet:secret@127.0.0.1:60522", "virt-agentpc")
	for _, want := range []string{
		"http://virt-agentpc:PORT/",
		"curl.exe -x http://127.0.0.1:41112 http://virt-agentpc:PORT/",
		"ssh virt-agentpc",
		"curl.exe -x socks5h://tsnet:secret@127.0.0.1:60522 http://virt-agentpc:PORT/",
	} {
		if !strings.Contains(withProxy, want) {
			t.Errorf("usageExamples(http) missing %q in:\n%s", want, withProxy)
		}
	}
	if strings.Contains(withProxy, "--install") {
		t.Errorf("usageExamples(http) should not suggest --install:\n%s", withProxy)
	}

	withoutProxy := usageExamples(false, "socks5h://tsnet:secret@127.0.0.1:60522", "machine-name")
	for _, want := range []string{"--install", "socks5h://tsnet:secret@127.0.0.1:60522"} {
		if !strings.Contains(withoutProxy, want) {
			t.Errorf("usageExamples(no http) missing %q in:\n%s", want, withoutProxy)
		}
	}
	if strings.Contains(withoutProxy, "127.0.0.1:41112") {
		t.Errorf("usageExamples(no http) must not advertise the inactive proxy:\n%s", withoutProxy)
	}
}

func TestControlURLLoopbackOnly(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:1234", "http://localhost:9", "http://[::1]:8080/"} {
		opts, err := parseControlURL(ok)
		if err != nil || opts != ok {
			t.Errorf("parseControlURL(%q) = %q, %v; want accepted", ok, opts, err)
		}
	}
	for _, bad := range []string{"https://controlplane.tailscale.com", "http://10.0.0.1:8080", "not a url", "http://evil.example:1"} {
		if _, err := parseControlURL(bad); err == nil {
			t.Errorf("parseControlURL(%q) accepted a non-loopback control server", bad)
		}
	}
}
