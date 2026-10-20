package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	sshBeginMarker = "# >>> PortableTailscale managed block (do not edit) >>>"
	sshEndMarker   = "# <<< PortableTailscale managed block <<<"
)

func sshConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

func sshHostList(peers peerList) string {
	if len(peers.Names) == 0 {
		return "*.ts.net"
	}
	return strings.Join(peers.Names, ", ")
}

const sshHostsPerLine = 8

func renderSSHBlock(exePath string, peers peerList) string {
	proxy := "ProxyCommand \"" + strings.ReplaceAll(exePath, "\\", "/") + "\" --stdio %h %p"

	var block strings.Builder
	block.WriteString(sshBeginMarker + "\n")
	for i := 0; i < len(peers.Names); i += sshHostsPerLine {
		end := min(i+sshHostsPerLine, len(peers.Names))
		block.WriteString("Host " + strings.Join(peers.Names[i:end], " ") + "\n")
		block.WriteString("  " + proxy + "\n\n")
	}
	block.WriteString("Host *.ts.net\n")
	block.WriteString("  " + proxy + "\n")
	block.WriteString(sshEndMarker + "\n")
	return block.String()
}

func installSSHConfig(path, exePath string, peers peerList) error {
	if exePath == "" {
		return errors.New("empty executable path")
	}
	return upsertSSHConfig(path, renderSSHBlock(exePath, peers))
}

func upsertSSHConfig(path, block string) error {
	content, mode, err := readSSHConfig(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		content, mode = "", 0600
	}
	next, changed := applySSHBlock(content, block)
	if !changed {
		return nil
	}
	return writeSSHConfig(path, next, mode)
}

func removeSSHConfig(path string) error {
	content, mode, err := readSSHConfig(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	next, changed := stripSSHBlocks(content)
	if !changed {
		return nil
	}
	return writeSSHConfig(path, next, mode)
}

func hasSSHBlock(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte(sshBeginMarker))
}

func applySSHBlock(content, block string) (string, bool) {
	clean, _ := stripSSHBlocks(content)
	next := block
	if clean != "" {
		next = block + "\n" + clean
	}
	return next, next != content
}

func stripSSHBlocks(content string) (string, bool) {
	changed := false
	for {
		start := strings.Index(content, sshBeginMarker)
		if start < 0 {
			break
		}
		endOffset := strings.Index(content[start:], sshEndMarker)
		if endOffset < 0 {
			break
		}
		end := start + endOffset + len(sshEndMarker)
		if end < len(content) && content[end] == '\n' {
			end++
		}
		if end < len(content) && content[end] == '\n' {
			end++
		}
		content = content[:start] + content[end:]
		changed = true
	}
	return content, changed
}

func readSSHConfig(path string) (string, os.FileMode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0600, err
	}

	mode := os.FileMode(0600)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}

	hadBOM := bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	if hadBOM {
		data = data[3:]
	}
	content := strings.ReplaceAll(string(data), "\r\n", "\n")
	return content, mode, nil
}

func writeSSHConfig(path, content string, mode os.FileMode) error {
	// Preserve the dominant line ending and a UTF-8 BOM if the file had one.
	original, err := os.ReadFile(path)
	if err == nil {
		if bytes.HasPrefix(original, []byte{0xEF, 0xBB, 0xBF}) {
			content = "\xEF\xBB\xBF" + content
		}
		if bytes.Contains(original, []byte("\r\n")) {
			content = strings.ReplaceAll(content, "\n", "\r\n")
		}
	}
	if mode == 0 {
		mode = 0600
	}
	return writeFileAtomic(path, []byte(content), mode)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".sshconfig-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}
