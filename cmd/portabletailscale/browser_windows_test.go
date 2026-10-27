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

	// A foreign setting is never touched.
	setTestAutoConfig(t, "http://corp.example/proxy.pac")
	if err := clearOrphanPAC(); err != nil {
		t.Fatal(err)
	}
	if current, err := readAutoConfigURL(); err != nil || current != "http://corp.example/proxy.pac" {
		t.Fatalf("foreign PAC was modified: %q, %v", current, err)
	}

	// An orphaned PAC with no prior is cleared: it points at a dead port.
	setTestAutoConfig(t, pacBaseURL()+"?t=stale&v=1")
	if err := clearOrphanPAC(); err != nil {
		t.Fatal(err)
	}
	if current, err := readAutoConfigURL(); err != nil || current != "" {
		t.Fatalf("orphaned PAC was not cleared: %q, %v", current, err)
	}

	// A live, backed-up install is restored rather than skipped: the marker
	// is not consulted, so it cannot leave a stale PAC alive.
	dataDir := t.TempDir()
	setTestAutoConfig(t, "http://corp.example/proxy.pac")
	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	if err := clearOrphanPAC(); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("AutoConfigURL = %q, want the trusted prior restored", got)
	}
}

// A well-formed planted marker must not suppress the orphan cleanup: a local
// writer cannot keep a stale loopback PAC alive by planting a marker of the
// right shape.
func TestClearOrphanPACIgnoresWellFormedPlantedMarker(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"","pacBase":"`+pacBaseURL()+`"}`) // planted, plausible
	setTestAutoConfig(t, pacBaseURL()+"?t=stale&v=1")

	if err := clearOrphanPAC(); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "" {
		t.Fatalf("planted marker suppressed cleanup, stale PAC left alive: %q", got)
	}

	// Same, with the marker claiming a foreign prior to bait a restore. The
	// current setting must be ours for a cleanup to apply at all.
	seedBackupFile(t, dataDir, `{"previous":"http://attacker.example/proxy.pac","pacBase":"`+pacBaseURL()+`"}`)
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacBaseURL()+"?t=stale&v=1")
	if err := clearOrphanPAC(); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("AutoConfigURL = %q, want the trusted HKCU prior", got)
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
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

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
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("deactivate rewrote AutoConfigURL to %q through a poisoned backup", got)
	}
}

// A marker this program could not have written is not an install of ours: it
// must not make the program treat the browser as configured for refresh.
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
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

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

// Uninstall with an invalid backup restores the trusted prior instead of
// blanking it — a corrupt marker must not cost the user their proxy setting —
// then drops the restore value and the file.
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
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("AutoConfigURL = %q, want the trusted prior restored", got)
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

// A planted marker of the right shape (our base, empty Previous) still must
// not stop install from capturing the real prior: gating capture on the file
// let a local writer make deactivate blank the user's proxy setting.
func TestBrowserInstallCapturesOverValidPlantedMarker(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"","pacBase":"`+pacBaseURL()+`"}`)
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != "http://corp.example/proxy.pac" {
		t.Fatalf("registry Previous = %q, %v, want the prior captured over the marker", previous, err)
	}

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("deactivate left %q, want the captured prior restored", got)
	}
}

// Deleting the marker file must not destroy the restore value: the trusted
// HKCU prior is still restored, so a local writer cannot blank the user's
// proxy setting by removing or corrupting the plantable file.
func TestBrowserDeactivateRestoresWhenMarkerMissing(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir() // no marker beside the executable
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("AutoConfigURL = %q, want the trusted prior restored", got)
	}
}

// Same for uninstall: restore from HKCU before dropping the value.
func TestBrowserUninstallRestoresWhenMarkerMissing(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := uninstallBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("AutoConfigURL = %q, want the trusted prior restored", got)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != "" {
		t.Fatalf("registry Previous = %q, %v, want deleted", previous, err)
	}
}

// An unreadable marker (here: a directory squatting the path) must not abort
// cleanup — a local principal could otherwise pin a stale PAC by holding or
// replacing the file.
func TestBrowserDeactivateCleansWhenMarkerUnreadable(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	if err := os.MkdirAll(browserBackupPath(dataDir), 0700); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "" {
		t.Fatalf("AutoConfigURL = %q, want our PAC cleared despite the unreadable marker", got)
	}
}

// The uninstall path must survive the same unreadable marker.
func TestBrowserUninstallCleansWhenMarkerUnreadable(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	if err := os.MkdirAll(browserBackupPath(dataDir), 0700); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := uninstallBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "" {
		t.Fatalf("AutoConfigURL = %q, want our PAC cleared despite the unreadable marker", got)
	}
}

// Installing with no current proxy means the user has none: a prior left by
// an earlier install must be dropped, or the next deactivate resurrects a
// proxy setting the user removed.
func TestBrowserInstallWithEmptyCurrentClearsStalePrevious(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != "" {
		t.Fatalf("registry Previous = %q, %v, want cleared for an empty current", previous, err)
	}

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "" {
		t.Fatalf("deactivate restored the stale prior %q, want empty", got)
	}
}

// isOurPACURL must not accept a foreign path that merely starts with our base.
func TestIsOurPACURLRequiresBoundary(t *testing.T) {
	if !isOurPACURL(pacBaseURL()) {
		t.Fatal("the bare PAC base is not recognized")
	}
	if !isOurPACURL(pacURLFor("tok", time.Unix(1, 0))) {
		t.Fatal("a tokenized PAC URL is not recognized")
	}
	for _, foreign := range []string{
		pacBaseURL() + "-evil",
		pacBaseURL() + "x?t=tok",
		"http://attacker.example/proxy.pac",
	} {
		if isOurPACURL(foreign) {
			t.Fatalf("isOurPACURL accepted the foreign URL %q", foreign)
		}
	}
}

// With no usable marker but a trusted prior in HKCU, the orphan clear
// restores the prior instead of blanking the user's setting.
func TestClearOrphanPACRestoresRegistryPrevious(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, "{not json") // unusable: purged, not a backup
	if err := writeBrowserPrevious("http://corp.example/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, pacURLFor("tok", time.Unix(1, 0)))

	if err := clearOrphanPAC(); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != "http://corp.example/proxy.pac" {
		t.Fatalf("AutoConfigURL = %q, want the trusted prior restored", got)
	}
}

// A marker path squatted by a directory must not block the PAC install.
func TestBrowserInstallSurvivesSquattedMarker(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	if err := os.MkdirAll(browserBackupPath(dataDir), 0700); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	pac := pacURLFor("tok", time.Unix(1, 0))
	if err := installBrowserPAC(dataDir, pac); err != nil {
		t.Fatalf("install blocked by a squatted marker: %v", err)
	}
	if got := readTestAutoConfig(t); got != pac {
		t.Fatalf("AutoConfigURL = %q, want %q", got, pac)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != "http://corp.example/proxy.pac" {
		t.Fatalf("registry Previous = %q, %v, want the prior captured", previous, err)
	}
}

// Reactivation must not be suppressed by an unreadable marker either.
func TestBrowserReactivateToleratesUnreadableMarker(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	if err := os.MkdirAll(browserBackupPath(dataDir), 0700); err != nil {
		t.Fatal(err)
	}
	setTestAutoConfig(t, "http://corp.example/proxy.pac")

	pac := pacURLFor("tok", time.Unix(1, 0))
	if err := reactivateBrowserPAC(dataDir, pac); err != nil {
		t.Fatalf("reactivation blocked by an unreadable marker: %v", err)
	}
	if got := readTestAutoConfig(t); got != pac {
		t.Fatalf("AutoConfigURL = %q, want %q", got, pac)
	}
}

// Our own marker must stay readable: a prior long enough to push the file
// past the bound its readers enforce drops the informational copy instead of
// growing past it, while HKCU keeps the prior verbatim for the restore.
func TestBrowserInstallDropsOversizedPreviousFromMarker(t *testing.T) {
	withTestRegistry(t)
	dataDir := t.TempDir()
	long := "http://corp.example/" + strings.Repeat("a", 5000)
	setTestAutoConfig(t, long)

	if err := installBrowserPAC(dataDir, pacURLFor("tok", time.Unix(1, 0))); err != nil {
		t.Fatal(err)
	}
	if previous, err := readBrowserPrevious(); err != nil || previous != long {
		t.Fatalf("registry Previous was not captured verbatim")
	}
	backup, ok, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil || !ok {
		t.Fatalf("our own marker became unreadable: ok=%v err=%v", ok, err)
	}
	if backup.Previous != "" {
		t.Fatalf("marker kept a %d-byte previous, want it dropped", len(backup.Previous))
	}

	if err := deactivateBrowserPAC(dataDir); err != nil {
		t.Fatal(err)
	}
	if got := readTestAutoConfig(t); got != long {
		t.Fatalf("deactivate did not restore the long prior")
	}
}

// A marker this program could write is accepted as an install; the shape is
// what "configured" means (deactivate no longer depends on it at all).
func TestBrowserConfiguredAcceptsOwnMarker(t *testing.T) {
	dataDir := t.TempDir()
	seedBackupFile(t, dataDir, `{"previous":"","pacBase":"`+pacBaseURL()+`"}`)
	if !browserConfigured(dataDir) {
		t.Fatal("a marker this program writes was rejected as not configured")
	}
}

