package main

import (
	"io"
	"log"
	"strings"
)

// The embedded Tailscale logs Windows proxy-discovery diagnostics through the
// standard library logger, e.g. winhttp error #12167 ("no WPAD script": the
// normal direct-internet case, which Tailscale itself treats as "go direct")
// plus its [RATELIMIT] echoes. tsnet's Logf is already logger.Discard; this
// filter is the last uncurated channel, so every entry naming tshttpproxy
// (the marker also appears inside the RATELIMIT echoes' quoted format) is
// dropped and everything else passes through.
const tshttpproxyMarker = "tshttpproxy:"

// noiseFilter drops log entries naming tshttpproxy. The standard library
// logger serializes whole entries through single Write calls, so matching
// the entry matches the line.
type noiseFilter struct{ next io.Writer }

func (f noiseFilter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), tshttpproxyMarker) {
		return len(p), nil
	}
	return f.next.Write(p)
}

func installLogNoiseFilter() {
	log.SetOutput(noiseFilter{next: log.Writer()})
}
