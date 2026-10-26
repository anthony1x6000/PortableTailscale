//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows/registry"

	"portabletailscale/internal/private"
)

var internetSettingsKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// portableTailscalePreviousValue holds the pre-install AutoConfigURL beside
// AutoConfigURL in the same HKCU key. Trust split: the exe-adjacent file is
// only the PACBase/existence marker (validated but plantable), while this
// per-user registry value — which other local principals cannot plant — is
// the restore authority for the prior setting.
const portableTailscalePreviousValue = "PortableTailscalePrevious"

// refreshWinINET is a variable so tests can avoid touching the live browser.
var refreshWinINET = func() {
	dll := syscall.NewLazyDLL("wininet.dll")
	proc := dll.NewProc("InternetSetOptionW")
	_, _, _ = proc.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	_, _, _ = proc.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

// readBrowserBackupBody reads at most browserBackupMaxSize+1 bytes and closes
// the handle before returning. It must close before the caller can unlink:
// Go opens files with FILE_SHARE_READ|FILE_SHARE_WRITE only, so on Windows a
// delete of a still-open path fails with a sharing violation (on Unix it
// would succeed), leaving the invalid backup to suppress cleanup.
func readBrowserBackupBody(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, browserBackupMaxSize+1))
}

// loadBrowserBackup returns the saved backup state. The read is bounded;
// a file this program could not have written — unparsable, planted with a
// foreign PACBase or a non-URL Previous, oversized, or from an incompatible
// format — is removed (best effort) and reported as absent so callers
// re-capture the real registry state or clean up instead of restoring
// attacker content. The file's Previous field is informational only;
// restores read readBrowserPrevious (see the trust split above). Pre-HKCU
// backups' Previous never restores; the first deactivate after upgrade
// clears fail-safe — migrating it would make the plantable file a restore
// source again.
func loadBrowserBackup(path string) (browserBackup, bool, error) {
	data, err := readBrowserBackupBody(path)
	if errors.Is(err, fs.ErrNotExist) {
		return browserBackup{}, false, nil
	}
	if err != nil {
		return browserBackup{}, false, err
	}
	var backup browserBackup
	var ok bool
	if len(data) <= browserBackupMaxSize {
		backup, ok = parseBrowserBackup(data)
	}
	if !ok {
		_ = os.Remove(path) // an invalid file must not linger or suppress cleanup
		return browserBackup{}, false, nil
	}
	return backup, true, nil
}

func saveBrowserBackup(path string, backup browserBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > browserBackupMaxSize {
		// Previous is informational and never restored from, so drop it
		// rather than write a file our own readers reject as oversized.
		data, err = json.MarshalIndent(browserBackup{PACBase: backup.PACBase}, "", "  ")
		if err != nil {
			return err
		}
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

// readBrowserPrevious returns the trusted prior AutoConfigURL, or "" when
// there is none. An absent value and a value we did not write as a string
// (wrong type, corrupt entry) both count as none — the latter is not a prior
// and must not wedge later install/deactivate/uninstall. A genuine read
// failure is still an error: it means we cannot know the prior, which the
// callers must not paper over by clearing the user's setting.
func readBrowserPrevious() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()

	value, _, err := key.GetStringValue(portableTailscalePreviousValue)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if errors.Is(err, registry.ErrUnexpectedType) {
		return "", nil // not a prior this program wrote
	}
	if err != nil {
		return "", err
	}
	return value, nil
}

func writeBrowserPrevious(value string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKeyPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if errors.Is(err, fs.ErrNotExist) && value == "" {
		return nil // nothing to delete from a key that does not exist
	}
	if err != nil {
		return err
	}
	defer key.Close()

	if value == "" {
		if err := key.DeleteValue(portableTailscalePreviousValue); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return key.SetStringValue(portableTailscalePreviousValue, value)
}

// isOurPACURL reports whether current points at this program's PAC: the base
// followed by nothing or by a query. A bare prefix match would also accept a
// foreign path such as "<base>-evil".
func isOurPACURL(current string) bool {
	rest, ok := strings.CutPrefix(current, pacBaseURL())
	return ok && (rest == "" || rest[0] == '?')
}

// restoreBrowserPrevious puts the trusted prior AutoConfigURL back: the HKCU
// value wins, and no prior clears. Callers check that the current setting is
// ours first. This is deliberately independent of the marker file — that
// file is plantable, so it must never decide whether the user's prior proxy
// survives, only whether this directory owns an install.
func restoreBrowserPrevious() error {
	previous, err := readBrowserPrevious()
	if err != nil {
		return err
	}
	if err := writeAutoConfigURL(previous); err != nil {
		return err
	}
	refreshWinINET()
	return nil
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
	// An unreadable marker counts as absent: plantable, so it must not be
	// able to block the install by being held open or replaced.
	_, exists, _ := loadBrowserBackup(path)
	// Capture the prior from the current setting alone, never from the
	// plantable marker: a planted marker of the right shape would otherwise
	// skip the capture and leave deactivate blanking the user's proxy.
	//   - foreign: the user's real prior, stored verbatim;
	//   - empty: no prior exists, so drop a value left by an earlier install
	//     (restoring it later would resurrect a proxy the user removed);
	//   - ours: a reinstall/upgrade-over, keep the stored prior — destroying
	//     the only restore copy would be unrecoverable.
	prior := ""
	switch {
	case current == "":
		if err := writeBrowserPrevious(""); err != nil {
			return err
		}
	case !isOurPACURL(current):
		// The registry is the trusted per-user hive: store a captured
		// foreign prior verbatim — including shapes the file field filters,
		// like file:// — so deactivate can always put it back.
		if err := writeBrowserPrevious(current); err != nil {
			return err
		}
		prior = storablePrevious(current)
	}
	if !exists {
		// Persisting the marker is best effort too: a path squatted by a
		// directory or held open must not block the PAC install. The restore
		// authority is HKCU, so a missing marker cannot lose the prior.
		_ = os.Remove(path)
		_ = saveBrowserBackup(path, browserBackup{PACBase: pacBaseURL(), Previous: prior})
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
	// An unreadable marker counts as absent, so a squatted or locked file
	// cannot suppress reactivation; installBrowserPAC re-captures instead.
	backup, exists, _ := loadBrowserBackup(browserBackupPath(dataDir))
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
	previous, err := readBrowserPrevious()
	if err != nil {
		return err
	}

	ours := isOurPACURL(current)
	restored := current == previous
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
// exits, or clears our PAC when there is no prior. The restore value comes
// from HKCU, which no other local principal can plant. The marker file is
// only read to drop a junk copy: neither its absence nor a read failure may
// gate the restore, or a local principal could pin a stale PAC by deleting,
// corrupting, or holding the file open. The backup stays so the next run can
// reactivate it.
func deactivateBrowserPAC(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	_, _, _ = loadBrowserBackup(browserBackupPath(dataDir)) // best-effort purge
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if !isOurPACURL(current) {
		return nil
	}
	return restoreBrowserPrevious()
}

// clearOrphanPAC retires a PAC that points at this program's loopback proxy
// when no backup exists beside the executable — left behind by an install
// from a different directory whose backup this one cannot restore from.
// Leaving it would keep browsers (and tailscale's own control client, via
// winhttp) pointed at a dead port. The trusted prior is restored, not
// blanked: HKCU still holds the user's real setting even when this
// directory's marker is gone. A concurrently running instance would need to
// re-install its PAC, but the alternative is a permanently stale setting.
//
// This runs after main's deactivateBrowserPAC, which already restored (or
// cleared) our PAC without consulting the marker; the browserConfigured gate
// only skips the redundant restore for an install this directory owns.
func clearOrphanPAC(dataDir string) error {
	if browserConfigured(dataDir) {
		return nil
	}
	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if !isOurPACURL(current) {
		return nil // never touch a foreign setting
	}
	return restoreBrowserPrevious()
}

// uninstallBrowserPAC restores the prior setting from HKCU, drops the
// restore value and the marker file. Like deactivate, an unreadable marker
// must not stop the restore.
func uninstallBrowserPAC(dataDir string) error {
	if dataDir == "" {
		return nil
	}
	path := browserBackupPath(dataDir)
	_, _, _ = loadBrowserBackup(path) // best-effort purge

	current, err := readAutoConfigURL()
	if err != nil {
		return err
	}
	if isOurPACURL(current) {
		if err := restoreBrowserPrevious(); err != nil {
			return err
		}
	}
	if err := writeBrowserPrevious(""); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	refreshWinINET()
	return nil
}
