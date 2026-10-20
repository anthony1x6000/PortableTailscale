//go:build windows

// Package private protects PortableTailscale's data directory with a Windows
// DACL instead of relying on the POSIX mode arguments, which Windows ignores.
package private

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Dir restricts dir and everything below it to the current user, SYSTEM and
// Administrators, dropping the install folder's inherited entries. New files
// inherit the protected directory DACL. It is best-effort: unreadable children
// are skipped, reparse points and hard links are refused, the rest are
// protected, and the first error is returned.
func Dir(dir string) error {
	var firstErr error
	// Windows applies inheritable ACEs only to newly created children, so an
	// upgraded install keeps the old ACL on tailscaled.state and profiles.
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return nil
		}
		// Junctions are not always reported as ModeSymlink on Windows. Refuse
		// reparse points so the walk never applies a DACL outside the tree.
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read attributes of %s: %w", path, err)
			}
			return nil
		}
		attrs, err := windows.GetFileAttributes(name)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read attributes of %s: %w", path, err)
			}
			return nil
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			if firstErr == nil {
				firstErr = fmt.Errorf("refusing to follow reparse point %s", path)
			}
			// WalkDir would otherwise descend into a junction and apply the
			// DACL to files outside the tree.
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			if err := protect(path, true); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("protect %s: %w", path, err)
			}
			return nil
		}
		// A hard link shares its ACL with the target outside the tree, so
		// protecting it would change a file Dir was never asked to touch.
		links, err := linkCount(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read link count of %s: %w", path, err)
			}
			return nil
		}
		if links > 1 {
			if firstErr == nil {
				firstErr = fmt.Errorf("refusing hard link %s", path)
			}
			return nil
		}
		if err := File(path); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("protect %s: %w", path, err)
		}
		return nil
	})
	return firstErr
}

// File restricts an existing file to the current user, SYSTEM and
// Administrators, dropping its inherited entries.
func File(path string) error { return protect(path, false) }

// linkCount reports how many directory entries share the file's data.
func linkCount(path string) (uint32, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return 0, err
	}
	return info.NumberOfLinks, nil
}

func protect(path string, inherit bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("build SYSTEM SID: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("build Administrators SID: %w", err)
	}
	inheritance := uint32(0)
	if inherit {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, sid := range []*windows.SID{user.User.Sid, system, admins} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build private ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("set private ACL: %w", err)
	}
	return nil
}
