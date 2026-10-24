package main

import (
	"errors"
	"fmt"
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

// Forward relay limits: a tailnet peer with ACL access must not be able to
// pin unbounded sockets on this host, and an idle connection must not live
// forever. The idle window is generous because interactive sessions (web GUIs
// with WebSocket keepalives) legitimately go quiet between pings.
const (
	forwardIdleTimeout = 10 * time.Minute
	forwardMaxConns    = 256
)

// serveForward relays every tailnet connection on ln to the local loopback
// port. It is the server half of the no-admin bridge: the listener lives
// inside the node's userspace network stack, so nothing is bound on the host
// and nothing can trigger the Windows firewall dialog.
func serveForward(ln net.Listener, localPort int) {
	slots := make(chan struct{}, forwardMaxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient failures (fd exhaustion and friends) must not
			// permanently kill the bridge; back off and keep serving.
			time.Sleep(100 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			// At capacity: refuse this connection rather than let a peer
			// accumulate pinned sockets.
			_ = conn.Close()
			continue
		}
		go func() {
			defer func() { <-slots }()
			relayConn(conn, localPort)
		}()
	}
}

func relayConn(conn net.Conn, localPort int) {
	defer conn.Close()
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort)), 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	// Each direction runs to EOF, then half-closes its destination so a
	// peer doing shutdown(SHUT_WR) is not left waiting; both sides close
	// once both directions have drained.
	done := make(chan struct{}, 2)
	go func() {
		copyConn(upstream, conn)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		copyConn(conn, upstream)
		closeWrite(conn)
		done <- struct{}{}
	}()
	<-done
	<-done
}

// copyConn moves bytes one way with an idle deadline in both directions, so
// abandoned connections eventually expire instead of pinning a socket.
func copyConn(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(forwardIdleTimeout))
		n, err := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(forwardIdleTimeout))
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
