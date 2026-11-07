package linux

import (
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"syscall"
)

const (
	BootstrapPath       = "/usr/local/libexec/agentguard-bootstrap"
	bootstrapEntry      = "/.agentguard/bootstrap"
	bootstrapMaxStrings = 256
)

// validateBootstrapConfig checks the C contract without recursively validating
// the outer launch frame. Both encoders share the same base constraints.
func validateBootstrapConfig(c Config) error {
	if err := c.validateBase(); err != nil {
		return err
	}
	if len(c.Argv) > bootstrapMaxStrings || len(c.Env) > bootstrapMaxStrings ||
		len(c.Argv[0]) >= 4096 || len(c.WorkingDir) >= 4096 {
		return fmt.Errorf("bootstrap argument/environment bounds exceeded")
	}
	approved := false
	for _, file := range c.Files {
		if overlaps(file.Target, "/.agentguard") || overlaps(file.Target, "/workspace") {
			return fmt.Errorf("file overlaps reserved bootstrap or writable area")
		}
		approved = approved || file.Target == c.Argv[0]
	}
	if !approved {
		return fmt.Errorf("guest executable is not in the approved file set")
	}
	for _, mount := range c.Mounts {
		if overlaps(mount.Target, "/.agentguard") ||
			(overlaps(mount.Target, "/workspace") && mount.Target != "/workspace") {
			return fmt.Errorf("mount overlaps reserved bootstrap or workspace root")
		}
	}
	return nil
}

// encodeBootstrapConfig implements the bounded C contract in BOOTSTRAP.md.
// No JSON parser, environment inheritance or PATH lookup is needed in C.
func encodeBootstrapConfig(c Config) ([]byte, error) {
	if err := validateBootstrapConfig(c); err != nil {
		return nil, err
	}
	size := 20
	fields := append([]string{c.WorkingDir}, c.Argv...)
	fields = append(fields, c.Env...)
	for _, field := range fields {
		if strings.ContainsRune(field, 0) || len(field) >= MaxConfigSize-size {
			return nil, fmt.Errorf("bootstrap configuration exceeds frame bounds")
		}
		size += len(field) + 1
	}
	data := make([]byte, 20, size)
	copy(data, "AGBOOT\x00\x01")
	binary.BigEndian.PutUint32(data[8:12], uint32(size-20))
	binary.BigEndian.PutUint32(data[12:16], uint32(len(c.Argv)))
	binary.BigEndian.PutUint32(data[16:20], uint32(len(c.Env)))
	for _, field := range fields {
		data = append(data, field...)
		data = append(data, 0)
	}
	return data, nil
}

// newBootstrapConfig must run after pivot_root, in the private writable /tmp.
// The read-only, unlinked file is intended to survive Cx; the confined test
// must prove this on the target host. No host-backed protocol FD is needed.
// tempDir is explicit so unit tests can use a private ordinary directory.
func newBootstrapConfig(c Config, tempDir string) (*os.File, error) {
	data, err := encodeBootstrapConfig(c)
	if err != nil {
		return nil, err
	}
	writer, err := os.CreateTemp(tempDir, ".agentguard-bootstrap-")
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	defer os.Remove(writer.Name())
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	reader, err := openSource(writer.Name(), false)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			reader.Close()
		}
	}()
	written, err := writer.Stat()
	if err != nil {
		return nil, err
	}
	read, err := reader.Stat()
	if err != nil || !os.SameFile(written, read) {
		return nil, fmt.Errorf("bootstrap configuration replaced before reopen")
	}
	if err := os.Remove(writer.Name()); err != nil {
		return nil, err
	}
	if err := closeVerified(writer); err != nil {
		return nil, err
	}
	read, err = reader.Stat()
	if err != nil {
		return nil, err
	}
	stat, valid := read.Sys().(*syscall.Stat_t)
	if !valid || stat.Nlink != 0 {
		return nil, fmt.Errorf("bootstrap configuration remains linked")
	}
	ok = true
	return reader, nil
}

// Called on the locked PID1 thread before Guest starts. The descriptor number
// is captured before Close invalidates os.File, and EBADF is checked directly.
func closeVerified(file *os.File) error {
	fd := file.Fd()
	if err := file.Close(); err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
	if errno != syscall.EBADF {
		return fmt.Errorf("descriptor closure was not confirmed")
	}
	return nil
}
