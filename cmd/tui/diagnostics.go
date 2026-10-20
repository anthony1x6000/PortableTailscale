//go:build windows

package main

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/charmbracelet/x/ansi"
)

var secretURL = regexp.MustCompile(`(?i)(?:socks5|https?)://[^\s]+`)

var errLogonFailed = errors.New("Windows rejected the username or password; for a Microsoft account use its email and account password (not a PIN)")

// rdpFailures maps FreeRDP connection error codes to an explanation the user
// can act on; the first one FreeRDP reports becomes the session error.
var rdpFailures = []struct {
	code string
	err  error
}{
	{"ERRCONNECT_LOGON_FAILURE", errLogonFailed},
	{"ERRCONNECT_WRONG_PASSWORD", errLogonFailed},
	{"ERRCONNECT_ACCOUNT_LOCKED_OUT", errors.New("the Windows account is locked out")},
	{"ERRCONNECT_ACCOUNT_DISABLED", errors.New("the Windows account is disabled")},
	{"ERRCONNECT_ACCOUNT_EXPIRED", errors.New("the Windows account has expired")},
	{"ERRCONNECT_PASSWORD_EXPIRED", errors.New("the Windows password has expired; change it on that computer first")},
	{"ERRCONNECT_PASSWORD_MUST_CHANGE", errors.New("the Windows password must be changed on that computer first")},
	{"ERRCONNECT_ACCOUNT_RESTRICTION", errors.New("the Windows account is not allowed to sign in remotely (blank passwords are refused)")},
	{"ERRCONNECT_LOGON_TYPE_NOT_GRANTED", errors.New("the account is not allowed Remote Desktop sign-in; add it to Remote Desktop Users")},
	{"ERRCONNECT_CONNECT_TRANSPORT_FAILED", errors.New("could not reach Remote Desktop on that computer; check it is on, on Tailscale, and has Remote Desktop enabled")},
}

// isDiagnosticNoise reports FreeRDP start-up chatter that is not about the
// connection: the build-options banner and the OpenSSL legacy-provider notice
// (this FreeRDP build carries its own MD4, so NTLM still works).
func isDiagnosticNoise(s string) bool {
	return strings.Contains(s, "[log_build_warn]") || strings.Contains(s, "OpenSSL LEGACY provider failed to load")
}

func redact(s string, secrets ...string) string {
	// Longest first: a short secret that is a substring of a longer one must
	// not leave the remainder of the longer value in place. Sort a copy so the
	// caller's slice is untouched.
	ordered := append([]string(nil), secrets...)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, secret := range ordered {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	s = secretURL.ReplaceAllString(s, "[URL redacted]")
	s = ansi.Strip(s)
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, s)
}

type diagnosticWriter struct {
	mu       sync.Mutex
	pending  string
	source   string
	secrets  []string
	events   chan<- sessionEvent
	dropping bool
	failure  error
}

func newDiagnosticWriter(source, secret string, events chan<- sessionEvent) *diagnosticWriter {
	w := &diagnosticWriter{source: source, events: events}
	w.AddSecret(secret)
	return w
}

// AddSecret adds a value to redact from every subsequent line, such as the
// generated tsnet proxy password carried in the FreeRDP /proxy argument.
func (w *diagnosticWriter) AddSecret(secret string) {
	if secret == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.secrets = append(w.secrets, secret)
}
func (w *diagnosticWriter) emit(s string) {
	if isDiagnosticNoise(s) {
		return
	}
	if w.failure == nil {
		for _, f := range rdpFailures {
			if strings.Contains(s, f.code) {
				w.failure = f.err
				break
			}
		}
	}
	// Diagnostics must never block child-process shutdown.
	select {
	case w.events <- sessionEvent{log: w.source + ": " + redact(s, w.secrets...)}:
	default:
	}
}
func (w *diagnosticWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, b := range p {
		if b == '\n' {
			if !w.dropping && w.pending != "" {
				w.emit(w.pending)
			}
			w.pending = ""
			w.dropping = false
			continue
		}
		if w.dropping {
			continue
		}
		w.pending += string([]byte{b})
		if len(w.pending) > 8192 {
			w.pending = ""
			w.dropping = true
			w.emit("[oversized diagnostic line omitted]")
		}
	}
	return len(p), nil
}

// Failure returns the first recognised connection error FreeRDP reported.
func (w *diagnosticWriter) Failure() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failure
}
func (w *diagnosticWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending != "" {
		w.emit(w.pending)
		w.pending = ""
	}
}
