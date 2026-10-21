package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	runtimeDirPrefix = "portable-tailscale-"
	runtimeDirMaxAge = 24 * time.Hour
)

// cleanupStaleRuntimeDirs removes temporary state left by a crashed run.
// A clean run deletes its own directory; this only bounds the leftovers.
func cleanupStaleRuntimeDirs(root string, maxAge time.Duration, now time.Time) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), runtimeDirPrefix) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if now.Sub(info.ModTime()) > maxAge {
			_ = os.RemoveAll(filepath.Join(root, entry.Name()))
		}
	}
}
