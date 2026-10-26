//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"portabletailscale/internal/private"
)

var internetSettingsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// portableTailscalePreviousValue holds the pre-install AutoConfigURL beside
// AutoConfigURL in the same HKCU key. Trust split: the exe-adjacent file is
// only the PACBase/existence marker (validated but plantable), while this
// per-user registry value — which other local principals cannot plant — is
// the restore authority for the prior setting.
const portableTailscalePreviousValue = "PortableTailscalePrevious"

// refreshWinINET is a variable so tests can avoid touching the live browser.
var refreshWinINET = func() {
	dll := syscall.NewLazyDLL("wininet.dll")
	proc := dll.NewProc("InternetSetOptionW")
	_, _, _ = proc.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	_, _, _ = proc.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

// readBrowserBackupBody reads at most browserBackupMaxSize+1 bytes and closes
// the handle before returning. It must close before the caller can unlink:
// Go opens files with FILE_SHARE_READ|FILE_SHARE_WRITE only, so on Windows a
// delete of a still-open path fails with a sharing violation (on Unix it
// would succeed), leaving the invalid backup to suppress cleanup.
func readBrowserBackupBody(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, browserBackupMaxSize+1))
}

// loadBrowserBackup returns the saved backup state. The read is bounded;
// a file this program could not have written — unparsable, planted with a
// foreign PACBase or a non-URL Previous, oversized, or from an incompatible
// format — is removed (best effort) and reported as absent so callers
// re-capture the real registry state or clean up instead of restoring
// attacker content. The file's Previous field is informational only;
// restores read readBrowserPrevious (see the trust split above). Pre-HKCU
// backups' Previous never restores; the first deactivate after upgrade
// clears fail-safe — migrating it would make the plantable file a restore
// source again.
func loadBrowserBackup(path string) (browserBackup, bool, error) {
	data, err := readBrowserBackupBody(path)
	if errors.Is(err, fs.ErrNotExist) {
		return browserBackup{}, false, nil
	}
	if err != nil {
		return browserBackup{}, false, err
	}
	var backup browserBackup
	var ok bool
	if len(data) <= browserBackupMaxSize {
		backup, ok = parseBrowserBackup(data)
	}
	if !ok {
		_ = os.Remove(path) // an invalid file must not linger or suppress cleanup
		return browserBackup{}, false, nil
	}
	return backup, true, nil
}

func saveBrowserBackup(path string, backup browserBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	_ = private.Dir(dir)
	temp, err := os.CreateTemp(dir, ".browser-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp.Name(), path); err != nil {
		return err
	}
	_ = private.File(path)
	return nil
}

func readAutoConfigURL() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()

	value, _, err := key.GetStringValue("AutoConfigURL")
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func writeAutoConfigURL(value string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if value == "" {
		if err := key.DeleteValue("AutoConfigURL"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return key.SetStringValue("AutoConfigURL", value)
}

func readBrowserPrevious() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()

	value, _, err := key.GetStringValue(portableTailscalePreviousValue)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func writeBrowserPrevious(value string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()

	if value == "" {
		if err := key.DeleteValue(portableTailscalePreviousValue); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return key.SetStringValue(portableTailscalePreviousValue, value)
}

func isOurPACURL(current string) bool {
	return strings.HasPrefix(current, pacBaseURL())
}

// clearOurPAC clears AutoConfigURL when it currently points at this
// program's PAC; a foreign setting is never touched.
func clearOurPAC() error {
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if !isOurPACURL(current) {
		return nil
	}
	if err := writeAutoConfigURL(""); err != nil {
		return err
	}
	refreshWinINET()
	return nil
}

// restoreBrowserPrevious puts the trusted prior AutoConfigURL back: the HKCU
// value wins, and no prior clears. Callers check that the current setting is
// ours first. This is deliberately independent of the marker file — that
// file is plantable, so it must never decide whether the user's prior proxy
// survives, only whether this directory owns an install.
func restoreBrowserPrevious() error {
	previous, err := readBrowserPrevious()
	if err != nil {
		return err
	}
	if err := writeAutoConfigURL(previous); err != nil {
		return err
	}
	refreshWinINET()
	return nil
}

func installBrowserPAC(dataDir, pacURL string) error {
	if dataDir == "" {
		return errors.New("no data directory")
	}
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}

	path := browserBackupPath(dataDir)
	_, exists, err := loadBrowserBackup(path)
	if err != nil {
		return err
	}
	// Capture the real prior whenever the current setting is foreign, never
	// gated on the marker file: a planted marker of the right shape would
	// otherwise skip the capture and leave deactivate blanking the user's
	// proxy setting instead of restoring it. An empty or ours current leaves
	// the stored value alone — destroying the only restore copy (an
	// upgrade-over or corrupt-file reinstall) would be unrecoverable.
	prior := ""
	if current != "" && !isOurPACURL(current) {
		// The registry is the trusted per-user hive: store a captured
		// foreign prior verbatim — including shapes the file field filters,
		// like file:// — so deactivate can always put it back.
		if err := writeBrowserPrevious(current); err != nil {
			return err
		}
		prior = storablePrevious(current)
	}
	if !exists {
		if err := saveBrowserBackup(path, browserBackup{PACBase: pacBaseURL(), Previous: prior}); err != nil {
			return err
		}
	}

	if err := writeAutoConfigURL(pacURL); err != nil {
		return err
	}
	refreshWinINET()
	return nil
}

func reactivateBrowserPAC(dataDir, pacURL string) error {
	if dataDir == "" {
		return nil
	}
	backup, exists, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil {
		return err
	}
	if !exists {
		return installBrowserPAC(dataDir, pacURL)
	}
	if backup.PACBase == "" {
		return nil
	}
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	previous, err := readBrowserPrevious()
	if err != nil {
		return err
	}

	ours := isOurPACURL(current)
	restored := current == previous
	if !ours && !restored {
		return nil
	}
	if err := writeAutoConfigURL(pacURL); err != nil {
		return err
	}
	refreshWinINET()
	return nil
}

// deactivateBrowserPAC puts the previous proxy setting back when the program
// exits, or clears our PAC when there is no prior. The restore value comes
// from HKCU, which no other local principal can plant; the marker file is
// only read to drop a junk copy and never gates the restore, so deleting or
// corrupting it cannot cost the user their proxy setting. The backup stays so
// the next run can reactivate it.
func deactivateBrowserPAC(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	if _, _, err := loadBrowserBackup(browserBackupPath(dataDir)); err != nil {
		return err
	}
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if !isOurPACURL(current) {
		return nil
	}
	return restoreBrowserPrevious()
}

// clearOrphanPAC removes a PAC that points at this program's loopback proxy
// when no backup exists beside the executable — left behind by an install
// from a different directory whose backup this one cannot restore from.
// Leaving it would keep browsers (and tailscale's own control client, via
// winhttp) pointed at a dead port. Only this program's PAC base is touched;
// a concurrently running instance would need to re-install its PAC, but the
// alternative is a permanently stale setting.
func clearOrphanPAC(dataDir string) error {
	if browserConfigured(dataDir) {
		return nil // deactivateBrowserPAC handles the backed-up case
	}
	return clearOurPAC()
}

// uninstallBrowserPAC restores the prior setting from HKCU, drops the
// restore value and the marker file. Like deactivate, it never consults the
// plantable marker for the restore decision.
func uninstallBrowserPAC(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	path := browserBackupPath(dataDir)
	if _, _, err := loadBrowserBackup(path); err != nil {
		return err
	}

	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if isOurPACURL(current) {
		if err := restoreBrowserPrevious(); err != nil {
			return err
		}
	}
	if err := writeBrowserPrevious(""); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	refreshWinINET()
	return nil
}
