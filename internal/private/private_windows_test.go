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
	if err := Dir(dir); err != nil {
		t.Fatal(err)
	}
	if !protected(t, dir) {
		t.Fatal("data directory still inherits its parent ACL")
	}
	file := filepath.Join(dir, "state")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := File(file); err != nil {
		t.Fatal(err)
	}
	if !protected(t, file) {
		t.Fatal("state file still inherits its parent ACL")
	}
}
