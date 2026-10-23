//go:build !windows

package main

import "errors"

func installBrowserPAC(dataDir, pacURL string) error {
	return errors.New("browser proxy setup requires Windows")
}

func reactivateBrowserPAC(dataDir, pacURL string) error {
	return nil
}

func deactivateBrowserPAC(dataDir string) error {
	return nil
}

func clearOrphanPAC(dataDir string) error {
	return nil
}

func uninstallBrowserPAC(dataDir string) error {
	return nil
}
