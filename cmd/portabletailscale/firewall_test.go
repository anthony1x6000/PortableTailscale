package main

import (
	"os"
	"testing"

	"tailscale.com/envknob"
)

var firewallKnobs = []string{"TS_DEBUG_ALWAYS_USE_DERP", "TS_DISABLE_PORTMAPPER"}

func TestAvoidWindowsFirewallPrompt(t *testing.T) {
	// t.Setenv restores the process env, but envknob.Setenv also mutates the
	// tsnet knob registry, which outlives the test; restore both to the
	// values the process started with.
	originals := map[string]string{}
	for _, name := range firewallKnobs {
		originals[name] = os.Getenv(name)
	}
	t.Cleanup(func() {
		for name, val := range originals {
			envknob.Setenv(name, val)
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
