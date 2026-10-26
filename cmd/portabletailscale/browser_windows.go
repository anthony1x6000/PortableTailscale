//go:build windows

package main

import (
	"encoding/json"
	"errors"
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

// loadBrowserBackup returns the saved backup state. A file this program could
// not have written — unparsable, planted with a foreign PACBase or a
// non-URL Previous, or from an incompatible format — is reported as absent so
// callers re-capture the real registry state instead of restoring attacker
// content. The file's Previous field is informational only; restores read
// readBrowserPrevious instead (see the trust split above).
func loadBrowserBackup(path string) (browserBackup, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return browserBackup{}, false, nil
	}
	if err != nil {
		return browserBackup{}, false, err
	}
	backup, ok := parseBrowserBackup(data)
	if !ok {
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

func installBrowserPAC(dataDir, pacURL string) error {
	if dataDir == "" {
		return errors.New("no data directory")
	}
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}

	path := browserBackupPath(dataDir)
	backup, exists, err := loadBrowserBackup(path)
	if err != nil {
		return err
	}
	if !exists {
		backup = browserBackup{PACBase: pacBaseURL()}
		if current != "" && !strings.HasPrefix(current, backup.PACBase) {
			backup.Previous = storablePrevious(current)
		}
		// The registry value is the restore authority; the file field is a
		// copy for inspection. An existing backup keeps its stored value.
		if err := writeBrowserPrevious(backup.Previous); err != nil {
			return err
		}
		if err := saveBrowserBackup(path, backup); err != nil {
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

	ours := strings.HasPrefix(current, backup.PACBase)
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
// exits. The file only proves the PAC is ours (PACBase); the value restored
// comes from HKCU, which no other local principal can plant. The backup
// stays so the next run can reactivate it.
func deactivateBrowserPAC(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	backup, exists, err := loadBrowserBackup(browserBackupPath(dataDir))
	if err != nil || !exists || backup.PACBase == "" {
		return err
	}
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(current, backup.PACBase) {
		return nil
	}
	previous, err := readBrowserPrevious()
	if err != nil {
		return err
	}
	if previous != "" {
		if err := writeAutoConfigURL(previous); err != nil {
			return err
		}
	} else if err := writeAutoConfigURL(""); err != nil {
		return err
	}
	refreshWinINET()
	return nil
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
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(current, pacBaseURL()) {
		return nil
	}
	if err := writeAutoConfigURL(""); err != nil {
		return err
	}
	refreshWinINET()
	return nil
}

func uninstallBrowserPAC(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	path := browserBackupPath(dataDir)
	backup, exists, err := loadBrowserBackup(path)
	if err != nil {
		return err
	}
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}

	if !exists {
		if strings.HasPrefix(current, pacBaseURL()) {
			if err := writeAutoConfigURL(""); err != nil {
				return err
			}
			refreshWinINET()
		}
		return nil
	}

	if backup.PACBase == "" {
		return nil
	}
	ours := strings.HasPrefix(current, backup.PACBase)
	if ours {
		previous, err := readBrowserPrevious()
		if err != nil {
			return err
		}
		if previous != "" {
			if err := writeAutoConfigURL(previous); err != nil {
				return err
			}
		} else if err := writeAutoConfigURL(""); err != nil {
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
