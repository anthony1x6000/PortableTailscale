package main

import (
	"bytes"
	"log"
	"testing"
)

func TestNoiseFilterDropsTSHTTPProxySpam(t *testing.T) {
	// Lines below are real console output reported by a Windows user; the
	// embedded Tailscale logs them through the standard library logger.
	tests := []struct {
		name string
		line string
		keep bool
	}{
		{
			name: "winhttp no WPAD script",
			line: `2026/10/26 08:43:50 tshttpproxy: winhttp: GetProxyForURL("https://controlplane.tailscale.com/"): winapi error #12167/0x2f87`,
			keep: false,
		},
		{
			name: "rate limit echo with drop count",
			line: `2026/10/26 09:04:05 [RATELIMIT] format("tshttpproxy: winhttp: GetProxyForURL(%q): %v/%#v") (743 dropped)`,
			keep: false,
		},
		{
			name: "rate limit echo",
			line: `2026/10/26 09:04:05 [RATELIMIT] format("tshttpproxy: winhttp: GetProxyForURL(%q): %v/%#v")`,
			keep: false,
		},
		{
			name: "cached proxy setting update",
			line: `2026/10/26 08:44:22 tshttpproxy: winhttp: updating cached proxy setting from <nil> to http://127.0.0.1:8080`,
			keep: false,
		},
		{
			name: "unrelated rate limit echo",
			line: `2026/10/26 09:04:05 [RATELIMIT] format("magicsock: derp(%v): %v") (2 dropped)`,
			keep: true,
		},
		{
			name: "unrelated log line",
			line: `2026/10/26 08:44:00 magicsock: [v1] derp-22 connected`,
			keep: true,
		},
		{
			name: "line without timestamp",
			line: `warning: cannot restrict runtime directory permissions`,
			keep: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			f := noiseFilter{next: &buf}

			n, err := f.Write([]byte(tt.line + "\n"))
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			if n != len(tt.line)+1 {
				t.Errorf("Write reported %d bytes, want %d", n, len(tt.line)+1)
			}

			if !tt.keep && buf.String() != "" {
				t.Errorf("spam line was not dropped; got %q", buf.String())
			}
			if tt.keep && buf.String() != tt.line+"\n" {
				t.Errorf("line was modified or dropped; got %q", buf.String())
			}
		})
	}
}

func TestInstallLogNoiseFilter(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	defer log.SetOutput(prev)
	log.SetOutput(&buf)
	installLogNoiseFilter()

	log.Printf("tshttpproxy: winhttp: GetProxyForURL(%q): winapi error #12167/0x2f87", "https://derp23d.tailscale.com/")
	if buf.Len() != 0 {
		t.Errorf("tshttpproxy spam reached the log output: %q", buf.String())
	}

	log.Printf("some other message")
	if buf.String() == "" {
		t.Errorf("unrelated log line was dropped")
	}
}
