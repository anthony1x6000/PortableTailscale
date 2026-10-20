package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderSSHBlock(t *testing.T) {
	block := renderSSHBlock(`C:\Program Files\Portable Tailscale\PortableTailscale.exe`, peerList{
		Names: []string{"home-server", "home-server.tail.ts.net"},
	})
	for _, want := range []string{
		sshBeginMarker,
		sshEndMarker,
		"Host home-server home-server.tail.ts.net",
		"Host *.ts.net",
		`ProxyCommand "C:/Program Files/Portable Tailscale/PortableTailscale.exe" --stdio %h %p`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("block missing %q:\n%s", want, block)
		}
	}
}

func TestRenderSSHBlockRejectsUnsafeNames(t *testing.T) {
	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: []string{
		"home-server",
		"evil\nProxyCommand calc",
		"bad*",
		"-oProxyCommand",
	}})
	if !strings.Contains(block, "home-server") {
		t.Fatal("valid peer missing")
	}
	for _, bad := range []string{"evil", "bad*", "-oProxyCommand"} {
		if strings.Contains(block, bad) {
			t.Errorf("unsafe peer %q leaked into SSH config", bad)
		}
	}
}

func TestRenderSSHBlockManyPeers(t *testing.T) {
	names := make([]string, 20)
	for i := range names {
		names[i] = fmt.Sprintf("host-%02d", i)
	}
	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: names})
	for _, name := range names {
		if !strings.Contains(block, name) {
			t.Errorf("block missing %s", name)
		}
	}
	if got := strings.Count(block, "Host "); got < 3 {
		t.Errorf("Host lines = %d, want at least 3", got)
	}
}

func TestUpsertCreatesMissingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "config")
	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: []string{"home-server"}})
	if err := upsertSSHConfig(path, block); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), sshBeginMarker) {
		t.Fatalf("block not written:\n%s", data)
	}
}

func TestUpsertSSHConfigPreservesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "config")
	original := "Host *\n  ServerAliveInterval 30\n"
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}

	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: []string{"home-server"}})
	if err := upsertSSHConfig(path, block); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(first), sshBeginMarker) {
		t.Fatalf("managed block not at the top:\n%s", first)
	}
	if !strings.Contains(string(first), original) {
		t.Fatalf("original content missing:\n%s", first)
	}

	if err := upsertSSHConfig(path, block); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("upsert is not idempotent")
	}

	if err := removeSSHConfig(path); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Fatalf("restored %q, want %q", restored, original)
	}
}

func TestSSHConfigPreservesBOMAndCRLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	original := append([]byte{0xEF, 0xBB, 0xBF}, []byte("Host *\r\n  ServerAliveInterval 30\r\n")...)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}

	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{})
	if err := upsertSSHConfig(path, block); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(updated, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("BOM was not preserved")
	}
	if !bytes.Contains(updated, []byte("\r\n")) {
		t.Fatal("CRLF was not preserved")
	}
	if bytes.Contains(bytes.ReplaceAll(updated, []byte("\r\n"), nil), []byte("\n")) {
		t.Fatal("mixed line endings introduced")
	}

	if err := removeSSHConfig(path); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("restored bytes differ:\n%q\n%q", restored, original)
	}
}

func TestDuplicateSSHBlocksCollapsed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: []string{"home-server"}})
	content := block + "\n" + block + "\nHost *\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upsertSSHConfig(path, block); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(updated), sshBeginMarker); got != 1 {
		t.Fatalf("begin markers = %d, want 1", got)
	}
	if !strings.Contains(string(updated), "Host *") {
		t.Fatal("user content was lost")
	}
}

func TestStripMalformedBlockLeavesContent(t *testing.T) {
	content := "Host *\n" + sshBeginMarker + "\nHost broken\n"
	stripped, changed := stripSSHBlocks(content)
	if changed {
		t.Fatal("malformed block should not be removed")
	}
	if stripped != content {
		t.Fatalf("content changed: %q", stripped)
	}
}

func TestRemoveOnlyManagedBlockRemovesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: []string{"home-server"}})
	if err := os.WriteFile(path, []byte(block), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeSSHConfig(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("empty ssh config was not removed")
	}
}

func TestRemoveMissingSSHConfig(t *testing.T) {
	if err := removeSSHConfig(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("remove missing config: %v", err)
	}
}

func TestApplySSHBlockIdempotent(t *testing.T) {
	content := "Host *\n  User me\n"
	block := renderSSHBlock("/opt/PortableTailscale.exe", peerList{Names: []string{"home-server"}})
	once, _ := applySSHBlock(content, block)
	twice, changed := applySSHBlock(once, block)
	if changed {
		t.Fatal("second apply reported a change")
	}
	if once != twice {
		t.Fatal("apply is not idempotent")
	}
}
