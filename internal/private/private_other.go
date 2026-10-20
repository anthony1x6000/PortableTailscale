//go:build !windows

// Package private protects PortableTailscale's data directory. On non-Windows
// platforms the existing POSIX modes already apply, so these are no-ops.
package private

// Dir leaves dir unchanged.
func Dir(string) error { return nil }

// File leaves path unchanged.
func File(string) error { return nil }
