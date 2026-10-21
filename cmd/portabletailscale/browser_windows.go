//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"portabletailscale/internal/private"
)

var internetSettingsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// refreshWinINET is a variable so tests can avoid touching the live browser.
var refreshWinINET = func() {
	dll := syscall.NewLazyDLL("wininet.dll")
	proc := dll.NewProc("InternetSetOptionW")
	_, _, _ = proc.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	_, _, _ = proc.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

type browserBackup struct {
	Previous string `json:"previous"`
	PACBase  string `json:"pacBase"`
}

func loadBrowserBackup(path string) (browserBackup, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return browserBackup{}, false, nil
	}
	if err != nil {
		return browserBackup{}, false, err
	}
	var backup browserBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return browserBackup{}, false, fmt.Errorf("parse %s: %w", path, err)
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
			backup.Previous = current
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

	ours := strings.HasPrefix(current, backup.PACBase)
	restored := current == backup.Previous
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
// exits. The backup stays so the next run can reactivate it.
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
	if backup.Previous != "" {
		if err := writeAutoConfigURL(backup.Previous); err != nil {
			return err
		}
	} else if err := writeAutoConfigURL(""); err != nil {
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
		if backup.Previous != "" {
			if err := writeAutoConfigURL(backup.Previous); err != nil {
				return err
			}
		} else if err := writeAutoConfigURL(""); err != nil {
			return err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	refreshWinINET()
	return nil
}
