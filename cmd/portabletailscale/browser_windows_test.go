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
	previous, err := readBrowserPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if previous != "http://corp.example/proxy.pac" {
		t.Fatalf("registry Previous = %q, want the pre-install AutoConfigURL", previous)
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
	if previous, err := readBrowserPrevious(); err != nil || previous != "" {
		t.Fatalf("registry Previous after uninstall = %q, %v, want deleted", previous, err)
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
	// A corrupt file is not restore state: treat it as absent, install
	// re-captures the real value, and the file is replaced with a valid
	// backup instead of aborting PAC management entirely.
	pac := pacURLFor("tok", time.Unix(1, 0))
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
		t.Fatalf("corrupt backup not replaced: ok=%v err=%v", ok, err)
	}
	if backup.Previous != "http://keep.example/pac" {
		t.Fatalf("re-captured previous = %q, want the pre-install value", backup.Previous)
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

func seedBackupFile(t *testing.T, dataDir, content string) {
	t.Helper()
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(browserBackupPath(dataDir), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeTestAutoConfig(t *testing.T, value string) {
	t.Helper()
	if err := writeAutoConfigURL(value); err != nil {
		t.Fatal(err)
	}
}

func readTestAutoConfig(t *testing.T) string {
	t.Helper()
	value, err := readAutoConfigURL()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// A backup with a widened PACBase is not one of ours: deactivate must never
// treat a foreign AutoConfigURL as ours and restore the poisoned Previous.
func TestBrowserDeactivateIgnoresPoisonedPACBase(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"http://127.0.0.1:9/pac","pacBase":"h"}`)
	writeTestAutoConfig(t, "http://corp.example/proxy.pac")

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("deactivate rewrote AutoConfigURL to %q through a poisoned backup", got)
	}
}

// A backup with a non-URL Previous is not one of ours either.
func TestBrowserDeactivateIgnoresPoisonedPrevious(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"not a url","pacBase":"`+pacBaseURL()+`"}`)
	writeTestAutoConfig(t, "http://corp.example/proxy.pac")

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("deactivate rewrote AutoConfigURL to %q through a poisoned backup", got)
	}
}

// A planted or corrupt backup file must not count as an install: it would
// otherwise mark the browser configured and suppress stale-PAC cleanup.
func TestBrowserConfiguredFalseForPlantedBackup(t *testing.T) {
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"http://127.0.0.1:9/pac","pacBase":"h"}`)
	if browserConfigured(dataDir) {
		t.Fatal("browserConfigured accepted a backup this program could not have written")
	}
}

// Install over a planted file must re-capture the real registry state and
// overwrite the planted file with a valid backup.
func TestBrowserInstallRecapturesOverPlantedBackup(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"http://127.0.0.1:9/pac","pacBase":"h"}`)
	writeTestAutoConfig(t, "http://corp.example/proxy.pac")

	pac := pacURLFor("tok", time.Unix(1, 0))
	if err := installBrowserPAC(dataDir, pac); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != pac {
		t.Fatalf("AutoConfigURL = %q, want %q", got, pac)
	}
	backup, ok, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil || !ok {
		t.Fatalf("backup not re-captured: ok=%v err=%v", ok, err)
	}
	if backup.Previous != "http://corp.example/proxy.pac" || backup.PACBase != pacBaseURL() {
		t.Fatalf("re-captured backup = %+v, want previous corp PAC and our base", backup)
	}
}

// The file is only the PACBase/existence marker: even a well-formed planted
// Previous with the correct base must never restore — the registry is the
// restore authority. With no registry Previous, deactivate clears.
func TestBrowserDeactivateIgnoresPlantedPreviousWithCorrectBase(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"http://attacker.example/pac","pacBase":"`+pacBaseURL()+`"}`)
	if err := writeBrowserPrevious(""); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "" {
		t.Fatalf("deactivate left %q, want cleared and never the planted Previous", got)
	}
}

// The pre-install value restores from HKCU, not from the file: a registry
// Previous wins over whatever the file claims.
func TestBrowserDeactivateRestoresRegistryPrevious(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"http://attacker.example/pac","pacBase":"`+pacBaseURL()+`"}`)
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("deactivate left %q, want the registry Previous", got)
	}
}

// The registry is the trusted per-user hive: a prior WinINET accepts but
// validPreviousURL refuses (file://) is captured verbatim there so restore
// always works; the informational file field still filters it to empty.
func TestBrowserInstallStoresFileURLPreviousVerbatim(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	setTestAutoConfig(t, "file:///C:/something")

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	previous, err := readBrowserPrevious()
	if err != nil {
		t.Fatal(err)
	}
	if previous != "file:///C:/something" {
		t.Fatalf("registry Previous = %q, want the file:// prior verbatim", previous)
	}
	backup, ok, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil || !ok {
		t.Fatalf("backup: ok=%v err=%v", ok, err)
	}
	if backup.Previous != "" {
		t.Fatalf("file Previous = %q, want the filtered empty copy", backup.Previous)
	}

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "file:///C:/something" {
		t.Fatalf("AutoConfigURL = %q, want the file:// prior restored", got)
	}
}

// An oversized backup file is not something we wrote: refuse to read it.
func TestBrowserConfiguredFalseForOversizedBackup(t *testing.T) {
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"","pacBase":"`+pacBaseURL()+`"}`+strings.Repeat(" ", 5000))
	if browserConfigured(dataDir) {
		t.Fatal("browserConfigured accepted an oversized backup file")
	}
}

// An invalid backup is not a reason to leave our PAC installed: deactivate
// still clears it and removes the unusable file.
func TestBrowserDeactivateCleansOurPACWhenBackupInvalid(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, "{not json")
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "" {
		t.Fatalf("AutoConfigURL = %q, want our PAC cleared", got)
	}
	if _, err := os.Stat(browserBackupPath(dataDir)); !os.IsNotExist(err) {
		t.Fatal("invalid backup file was not removed")
	}
}

// Uninstall with an invalid backup: our PAC cleared, registry Previous
// deleted, file removed.
func TestBrowserUninstallCleansWhenBackupInvalid(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, "{not json")
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := uninstallBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "" {
		t.Fatalf("AutoConfigURL = %q, want our PAC cleared", got)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != "" {
		t.Fatalf("registry Previous = %q, %v, want deleted", previous, err)
	}
	if _, err := os.Stat(browserBackupPath(dataDir)); !os.IsNotExist(err) {
		t.Fatal("invalid backup file was not removed")
	}
}

// Corrupting the exe-adjacent file must not destroy the restore value:
// install over an ours current leaves the stored registry Previous alone.
func TestBrowserInstallPreservesRegistryPreviousWhenCurrentIsOurs(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, "{not json")
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(2, 0))); err != nil {
		t.Fatal(err)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != "http://corp.example/proxy.pac" {
		t.Fatalf("registry Previous = %q, %v, want preserved", previous, err)
	}
}

// An oversized file is treated as absent: loadBrowserBackup reports it so
// and removes it, then install re-captures over it.
func TestBrowserOversizedBackupTreatedAsAbsent(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"","pacBase":"`+pacBaseURL()+`"}`+strings.Repeat(" ", 5000))
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	if _, ok, err := loadBrowserBackup(browserBackupPath(dataDir)); err != nil || ok {
		t.Fatalf("oversized backup reported ok=%v err=%v, want absent", ok, err)
	}
	if _, err := os.Stat(browserBackupPath(dataDir)); !os.IsNotExist(err) {
		t.Fatal("oversized backup file was not removed")
	}

	pac := pacURLFor("tok", time.Unix(1, 0))
	if err := installBrowserPAC(dataDir, pac); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != pac {
		t.Fatalf("AutoConfigURL = %q, want re-captured install %q", got, pac)
	}
	backup, ok, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil || !ok {
		t.Fatalf("backup not re-captured: ok=%v err=%v", ok, err)
	}
	if backup.Previous != "http://corp.example/proxy.pac" {
		t.Fatalf("re-captured previous = %q", backup.Previous)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != "http://corp.example/proxy.pac" {
		t.Fatalf("registry Previous = %q, %v, want re-captured", previous, err)
	}
}
