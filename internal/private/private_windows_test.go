//go:build windows

package private

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func protected(t *testing.T, path string) bool {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}
	return control&windows.SE_DACL_PROTECTED != 0
}

func TestDirAndFileProtectInheritance(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// A state file from an earlier version must be protected too: Windows only
	// applies new inheritable ACEs to children created after the directory DACL.
	existing := filepath.Join(dir, "tailscaled.state")
	if err := os.WriteFile(existing, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(dir, "nested")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	nestedFile := filepath.Join(nested, "old")
	if err := os.WriteFile(nestedFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Dir(dir); err != nil {
		t.Fatal(err)
	}
	if !protected(t, dir) {
		t.Fatal("data directory still inherits its parent ACL")
	}
	if !protected(t, existing) {
		t.Fatal("existing state file still inherits its parent ACL")
	}
	if !protected(t, nested) || !protected(t, nestedFile) {
		t.Fatal("existing subdirectory or its file still inherits its parent ACL")
	}
	file := filepath.Join(dir, "rdp-profiles.json")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := File(file); err != nil {
		t.Fatal(err)
	}
	if !protected(t, file) {
		t.Fatal("profile file still inherits its parent ACL")
	}
}

func TestDirRejectsReparsePoint(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a test symlink: %v", err)
	}
	if err := Dir(link); err == nil {
		t.Fatal("followed a reparse point while applying the ACL")
	}
}
