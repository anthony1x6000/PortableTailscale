package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
)

// browserBackup records the WinINET AutoConfigURL state this program changed.
// The file lives in the executable-adjacent data directory, where other local
// principals may be able to plant or replace it (FAT/exFAT installs have no
// ACLs), so nothing may restore from it without validating the content first.
type browserBackup struct {
	Previous string `json:"previous"`
	PACBase  string `json:"pacBase"`
}

// validBrowserBackup reports whether b is a backup this program could have
// written: the PAC base must be exactly our constant base (never a widened
// attacker-chosen prefix), and a prior AutoConfigURL must be an absolute
// http(s) URL without userinfo or fragment.
func validBrowserBackup(b browserBackup) bool {
	if b.PACBase != pacBaseURL() {
		return false
	}
	if b.Previous == "" {
		return true
	}
	u, err := url.Parse(b.Previous)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return u.User == nil && u.Fragment == ""
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

// browserConfigured reports whether a browser install this program recognizes
// exists. A backup file only counts when it is one we could have written;
// a planted or corrupt file must not mark an install (it would otherwise
// suppress stale-PAC cleanup) — install re-captures over it instead.
func browserConfigured(dataDir string) bool {
	if dataDir == "" {
		return false
	}
	data, err := os.ReadFile(browserBackupPath(dataDir))
	if err != nil {
		return false
	}
	_, ok := parseBrowserBackup(data)
	return ok
}
