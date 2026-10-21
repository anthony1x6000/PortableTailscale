package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupStaleRuntimeDirs(t *testing.T) {
	root := t.TempDir()
	old := filepath.Join(root, runtimeDirPrefix+"old")
	fresh := filepath.Join(root, runtimeDirPrefix+"fresh")
	other := filepath.Join(root, "other-dir")
	file := filepath.Join(root, runtimeDirPrefix+"file")

	for _, dir := range []string{old, fresh, other} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	if err := os.Chtimes(old, now.Add(-25*time.Hour), now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(other, now.Add(-48*time.Hour), now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}

	cleanupStaleRuntimeDirs(root, runtimeDirMaxAge, now)

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("stale runtime directory was not removed")
	}
	for _, keep := range []string{fresh, other, file} {
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("expected %s to survive cleanup: %v", keep, err)
		}
	}
}

func TestCleanupStaleRuntimeDirsMissingRoot(t *testing.T) {
	cleanupStaleRuntimeDirs(filepath.Join(t.TempDir(), "missing"), runtimeDirMaxAge, time.Now())
}
