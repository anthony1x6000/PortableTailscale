package main

import (
	"strconv"
	"testing"
)

func FuzzSplitTarget(f *testing.F) {
	for _, seed := range []string{"home-server:22", "home-server", "[::1]:443", "example.com:abc", "", "a b:1"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, addr string) {
		host, port, err := splitTarget(addr, "443")
		if err != nil {
			return
		}
		if host == "" {
			t.Fatal("accepted an empty host")
		}
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			t.Fatalf("accepted invalid port %q", port)
		}
	})
}

func FuzzApplySSHBlock(f *testing.F) {
	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: []string{"home-server"}})
	for _, seed := range []string{"", "Host *\n", "Host *\n  User me\n", "junk\nmore\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		once, _ := applySSHBlock(content, block)
		twice, changed := applySSHBlock(once, block)
		if changed {
			t.Fatal("second apply reported a change")
		}
		if once != twice {
			t.Fatal("apply is not idempotent")
		}
	})
}
