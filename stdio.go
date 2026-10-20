package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func runStdio(args []string) int {
	target, err := stdioTarget(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "PortableTailscale:", err)
		return 2
	}

	conn, buffered, err := connectViaProxy(localProxyAddr, target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "PortableTailscale:", err)
		return 1
	}
	defer conn.Close()

	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		closeWrite(conn)
	}()

	_, _ = io.Copy(os.Stdout, buffered)
	_ = conn.Close()
	return 0
}

func stdioTarget(args []string) (string, error) {
	switch len(args) {
	case 1:
		host, port, err := splitTarget(args[0], "22")
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(host, port), nil
	case 2:
		host := strings.Trim(args[0], "[]")
		host, port, err := splitTarget(net.JoinHostPort(host, args[1]), "22")
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(host, port), nil
	default:
		return "", errors.New("usage: --stdio HOST PORT")
	}
}

func connectViaProxy(proxyAddr, target string) (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("local proxy is not running: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}})
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("read proxy response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("local proxy refused %s: %s %s", target, resp.Status, strings.TrimSpace(string(body)))
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, reader, nil
}
