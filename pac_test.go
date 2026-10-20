package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildPAC(t *testing.T) {
	pac := buildPAC("127.0.0.1:41112", peerList{Names: []string{"home-server", "home-server.tail.ts.net"}, IPs: []string{"100.64.0.1"}})
	for _, want := range []string{
		"function FindProxyForURL",
		`"home-server"`,
		`"home-server.tail.ts.net"`,
		`"100.64.0.1"`,
		`PROXY 127.0.0.1:41112`,
		`DIRECT`,
	} {
		if !strings.Contains(pac, want) {
			t.Errorf("PAC missing %q:\n%s", want, pac)
		}
	}
}

func TestPACInNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("REQUIRE_NODE") != "" {
			t.Fatal("node is required but not on PATH")
		}
		t.Skip("node not on PATH")
	}

	pac := buildPAC(localProxyAddr, peerList{
		Names: []string{"home-server", "home-server.tail.ts.net"},
		IPs:   []string{"100.64.0.1"},
	})
	pacPath := filepath.Join(t.TempDir(), "proxy.pac")
	if err := os.WriteFile(pacPath, []byte(pac), 0600); err != nil {
		t.Fatal(err)
	}

	const script = `
const fs = require('fs');
const vm = require('vm');
const pac = fs.readFileSync(process.env.PAC_PATH, 'utf8');
const sandbox = { dnsDomainIs: (host, suffix) => host.endsWith(suffix) };
vm.createContext(sandbox);
vm.runInContext(pac, sandbox);
const fn = vm.runInContext('FindProxyForURL', sandbox);
const q = (host) => fn('http://' + host + '/', host);
console.log(JSON.stringify({
  short: q('home-server'),
  upper: q('HOME-SERVER'),
  fqdn: q('home-server.tail.ts.net'),
  other: q('example.com'),
  ip: q('100.64.0.1'),
  unknown: q('unknown.tail.ts.net'),
  internet: q('8.8.8.8')
}));
`
	cmd := exec.Command(node, "-e", script)
	cmd.Env = append(os.Environ(), "PAC_PATH="+pacPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, output)
	}

	var got map[string]string
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("parse node output %q: %v", output, err)
	}
	proxy := "PROXY " + localProxyAddr
	for _, key := range []string{"short", "upper", "fqdn", "ip"} {
		if got[key] != proxy {
			t.Errorf("%s = %q, want %q", key, got[key], proxy)
		}
	}
	for _, key := range []string{"other", "unknown", "internet"} {
		if got[key] != "DIRECT" {
			t.Errorf("%s = %q, want DIRECT", key, got[key])
		}
	}
}
