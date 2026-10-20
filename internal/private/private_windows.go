//go:build windows

// Package private protects PortableTailscale's data directory with a Windows
// DACL instead of relying on the POSIX mode arguments, which Windows ignores.
package private

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// Dir restricts dir and the files created in it to the current user, SYSTEM
// and Administrators, dropping the install folder's inherited entries.
func Dir(dir string) error { return protect(dir, true) }

// File restricts an existing file to the current user, SYSTEM and
// Administrators, dropping its inherited entries.
func File(path string) error { return protect(path, false) }

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
