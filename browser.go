package main

import (
	"os"
	"path/filepath"
)

func browserBackupPath(dataDir string) string {
	return filepath.Join(dataDir, "browser-proxy.json")
}

func browserConfigured(dataDir string) bool {
	if dataDir == "" {
		return false
	}
	_, err := os.Stat(browserBackupPath(dataDir))
	return err == nil
}
