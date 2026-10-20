//go:build !windows

package main

import "errors"

func installBrowserPAC(dataDir, pacURL string) error {
	return errors.New("browser proxy setup requires Windows")
}

func refreshBrowserPAC(dataDir, pacURL string) error {
	return nil
}

func uninstallBrowserPAC(dataDir string) error {
	return nil
}
