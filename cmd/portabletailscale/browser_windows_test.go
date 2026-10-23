//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func withTestRegistry(t *testing.T) {
	t.Helper()
	keyPath := fmt.Sprintf(`Software\PortableTailscaleTest-%d`, os.Getpid())
	key, _, err := registry.CreateKey(registry.CURRENT_USER, keyPath, registry.ALL_ACCESS)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Close()

	oldPath := internetSettingsKeyPath
	internetSettingsKeyPath = keyPath
	oldRefresh := refreshWinINET
	refreshWinINET = func() {}
	t.Cleanup(func() {
		internetSettingsKeyPath = oldPath
		refreshWinINET = oldRefresh
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	})
}

func setTestAutoConfig(t *testing.T, value string) {
	t.Helper()
	if err := writeAutoConfigURL(value); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserInstallRestore(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	pac := pacURLFor("tok", time.Unix(123, 0))
	if err := installBrowserPAC(dataDir, pac); err != nil {
		t.Fatal(err)
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != pac {
		t.Fatalf("AutoConfigURL = %q, want %q", current, pac)
	}

	backup, ok, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil || !ok {
		t.Fatalf("backup: ok=%v err=%v", ok, err)
	}
	if backup.Previous != "http://corp.example/proxy.pac" {
		t.Fatalf("previous = %q", backup.Previous)
	}

	if err := uninstallBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	current, err = readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != "http://corp.example/proxy.pac" {
		t.Fatalf("restored %q", current)
	}
	if _, err := os.Stat(browserBackupPath(dataDir)); !os.IsNotExist(err) {
		t.Fatal("backup file was not removed")
	}
}

func TestBrowserInstallWithoutPrevious(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()

	pac := pacURLFor("tok", time.Unix(1, 0))
	if err := installBrowserPAC(dataDir, pac); err != nil {
		t.Fatal(err)
	}
	if err := uninstallBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != "" {
		t.Fatalf("AutoConfigURL = %q, want empty", current)
	}
}

func TestBrowserReinstallKeepsOriginalBackup(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(2, 0))); err != nil {
		t.Fatal(err)
	}
	backup, _, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil {
		t.Fatal(err)
	}
	if backup.Previous != "http://corp.example/proxy.pac" {
		t.Fatalf("previous = %q", backup.Previous)
	}
}

func TestBrowserUninstallLeavesUserChange(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, "http://user.example/pac")
	if err := uninstallBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != "http://user.example/pac" {
		t.Fatalf("user PAC was overwritten: %q", current)
	}
}

func TestBrowserDeactivateAndReactivate(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	first := pacURLFor("one", time.Unix(1, 0))
	if err := installBrowserPAC(dataDir, first); err != nil {
		t.Fatal(err)
	}
	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != "http://corp.example/proxy.pac" {
		t.Fatalf("deactivate left %q", current)
	}
	if _, err := os.Stat(browserBackupPath(dataDir)); err != nil {
		t.Fatalf("backup removed on deactivate: %v", err)
	}

	second := pacURLFor("two", time.Unix(2, 0))
	if err := reactivateBrowserPAC(dataDir, second); err != nil {
		t.Fatal(err)
	}
	current, err = readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != second {
		t.Fatalf("reactivate left %q, want %q", current, second)
	}
}

func TestBrowserDeactivateWithoutPrevious(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()

	if err := installBrowserPAC(dataDir, pacURLFor("one", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != "" {
		t.Fatalf("deactivate left %q, want empty", current)
	}
}

func TestBrowserCorruptBackup(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	setTestAutoConfig(t, "http://keep.example/pac")
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(browserBackupPath(dataDir), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err == nil {
		t.Fatal("expected a parse error")
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != "http://keep.example/pac" {
		t.Fatalf("value changed after corrupt backup: %q", current)
	}
}

func TestBrowserReactivateUpdatesOurs(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()

	first := pacURLFor("tok", time.Unix(1, 0))
	second := pacURLFor("tok", time.Unix(2, 0))
	if err := installBrowserPAC(dataDir, first); err != nil {
		t.Fatal(err)
	}
	if err := reactivateBrowserPAC(dataDir, second); err != nil {
		t.Fatal(err)
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if current != second {
		t.Fatalf("AutoConfigURL = %q, want %q", current, second)
	}
}

func TestBrowserReactivateIgnoresForeignPAC(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, "http://someone-else/pac")
	if err := reactivateBrowserPAC(dataDir, pacURLFor("tok", time.Unix(2, 0))); err != nil {
		t.Fatal(err)
	}
	current, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(current, "http://someone-else/pac") {
		t.Fatalf("foreign PAC was replaced: %q", current)
	}
}

func TestClearOrphanPAC(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir() // no backup here: the orphan case

	setTestAutoConfig(t, "http://corp.example/proxy.pac")
	if err := clearOrphanPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if current, err := readAutoConfigURL(); err != nil || current != "http://corp.example/proxy.pac" {
		t.Fatalf("foreign PAC was modified: %q, %v", current, err)
	}

	setTestAutoConfig(t, pacBaseURL()+"?t=stale&v=1")
	if err := clearOrphanPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if current, err := readAutoConfigURL(); err != nil || current != "" {
		t.Fatalf("orphaned PAC was not cleared: %q, %v", current, err)
	}

	// With a local backup the restore belongs to deactivateBrowserPAC.
	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacBaseURL()+"?t=live&v=2")
	if err := clearOrphanPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if current, err := readAutoConfigURL(); err != nil || current != pacBaseURL()+"?t=live&v=2" {
		t.Fatalf("backed-up PAC was touched by the orphan clear: %q, %v", current, err)
	}
}
