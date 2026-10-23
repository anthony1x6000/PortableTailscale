package main

import (
	"os"
	"testing"

	"tailscale.com/envknob"
)

var firewallKnobs = []string{"TS_DEBUG_ALWAYS_USE_DERP", "TS_DISABLE_PORTMAPTER"}

func TestAvoidWindowsFirewallPrompt(t *testing.T) {
	// t.Setenv restores the process env, but envknob.Setenv also mutates the
	// tsnet knob registry, which outlives the test; reset both.
	t.Cleanup(func() {
		for _, name := range firewallKnobs {
			envknob.Setenv(name, "")
		}
	})
	for _, name := range firewallKnobs {
		t.Setenv(name, "")
	}

	avoidWindowsFirewallPrompt("linux")
	for _, name := range firewallKnobs {
		if got := os.Getenv(name); got != "" {
			t.Fatalf("%s = %q on a non-Windows GOOS; direct UDP networking must stay enabled", name, got)
		}
	}

	avoidWindowsFirewallPrompt("windows")
	for _, name := range firewallKnobs {
		if got := os.Getenv(name); got != "1" {
			t.Fatalf("%s = %q on windows; every non-loopback UDP bind must be disabled", name, got)
		}
	}
}
