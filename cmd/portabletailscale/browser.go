package main

import (
	"encoding/json"
	"io"
	"net/url"
	"os"
	"path/filepath"
)

// browserBackup records the WinINET AutoConfigURL state this program changed.
// The file lives in the executable-adjacent data directory, where other local
// principals may be able to plant or replace it (FAT/exFAT installs have no
// ACLs), so it is only the PACBase/existence marker: restore authority for
// the prior AutoConfigURL is the per-user registry value (browser_windows.go),
// and the Previous field here is informational.
type browserBackup struct {
	Previous string `json:"previous"`
	PACBase  string `json:"pacBase"`
}

// validPreviousURL reports whether v is an absolute http(s) URL with a host
// and no userinfo or fragment — the shape that may be restored into
// AutoConfigURL. Empty is the caller's decision.
func validPreviousURL(v string) bool {
	u, err := url.Parse(v)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.User == nil && u.Fragment == ""
}

// validBrowserBackup reports whether b is a backup this program could have
// written: the PAC base must be exactly our constant base (never a widened
// attacker-chosen prefix), and a prior AutoConfigURL must be an absolute
// http(s) URL without userinfo or fragment.
func validBrowserBackup(b browserBackup) bool {
	if b.PACBase != pacBaseURL() {
		return false
	}
	return b.Previous == "" || validPreviousURL(b.Previous)
}

// storablePrevious filters a captured prior for the informational file
// field: only a value validPreviousURL accepts is written there, anything
// else (e.g. a file:// URL WinINET accepts) is written empty. The registry —
// the restore authority — keeps the prior verbatim.
func storablePrevious(v string) string {
	if v == "" || validPreviousURL(v) {
		return v
	}
	return ""
}

// parseBrowserBackup decodes a backup file body and reports whether it is one
// of ours. Anything else — unparsable, planted, or from an incompatible
// future format — is not usable as restore state.
func parseBrowserBackup(data []byte) (browserBackup, bool) {
	var b browserBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return browserBackup{}, false
	}
	return b, validBrowserBackup(b)
}

func browserBackupPath(dataDir string) string {
	return filepath.Join(dataDir, "browser-proxy.json")
}

// browserBackupMaxSize bounds reads of the untrusted exe-adjacent file; a
// real backup is a few hundred bytes.
const browserBackupMaxSize = 4096

// browserConfigured reports whether a browser install this program recognizes
// exists. A backup file only counts when it is one we could have written;
// a planted, corrupt, or oversized file must not mark an install (it would
// otherwise suppress stale-PAC cleanup) — install re-captures over it instead.
func browserConfigured(dataDir string) bool {
	if dataDir == "" {
		return false
	}
	file, err := os.Open(browserBackupPath(dataDir))
	if err != nil {
		return false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, browserBackupMaxSize+1))
	if err != nil || len(data) > browserBackupMaxSize {
		return false
	}
	_, ok := parseBrowserBackup(data)
	return ok
}
