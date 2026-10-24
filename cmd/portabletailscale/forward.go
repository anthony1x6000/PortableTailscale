package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// forwardSpec is one tailnet-port to local-loopback-port bridge.
type forwardSpec struct {
	TailnetPort int
	LocalPort   int
}

// parseForwards validates repeated --forward flags of the form
// TAILNET_PORT:LOCAL_PORT. Both ports must be 1-65535; the format is strict so
// mistakes fail at startup instead of at connect time.
func parseForwards(raw []string) ([]forwardSpec, error) {
	specs := make([]forwardSpec, 0, len(raw))
	for _, arg := range raw {
		from, to, ok := strings.Cut(arg, ":")
		if !ok {
			return nil, fmt.Errorf("--forward %q: want TAILNET_PORT:LOCAL_PORT", arg)
		}
		spec := forwardSpec{}
		for _, part := range []struct {
			text string
			dest *int
		}{{from, &spec.TailnetPort}, {to, &spec.LocalPort}} {
			port, err := strconv.Atoi(part.text)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("--forward %q: port %q must be 1-65535", arg, part.text)
			}
			*part.dest = port
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// serveForward relays every tailnet connection on ln to the local loopback
// port. It is the server half of the no-admin bridge: the listener lives
// inside the node's userspace network stack, so nothing is bound on the host
// and nothing can trigger the Windows firewall dialog.
func serveForward(ln net.Listener, localPort int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go relayConn(conn, localPort)
	}
}

func relayConn(conn net.Conn, localPort int) {
	defer conn.Close()
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	// Both directions must drain: HTTP keep-alive and WebSocket frames ride
	// the same pair, and tearing down on the first EOF would truncate them.
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
	<-done
	<-done
}
