package linux

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const oPath = 0x200000

// openSource pins every path component with openat and rejects symlinks. A
// later rename cannot redirect a previously authorized source to another file.
func openSource(name string, directory bool) (*os.File, error) {
	if !cleanAbsolute(name) || name == "/" {
		return nil, fmt.Errorf("invalid source path")
	}
	fd, err := syscall.Open("/", oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	for i, part := range parts {
		flags := syscall.O_CLOEXEC | syscall.O_NOFOLLOW | oPath | syscall.O_DIRECTORY
		if i == len(parts)-1 && !directory {
			flags = syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_RDONLY | syscall.O_NONBLOCK
		}
		next, openErr := syscall.Openat(fd, part, flags, 0)
		syscall.Close(fd)
		if openErr != nil {
			return nil, openErr
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), name)
	info, err := f.Stat()
	if err != nil || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		f.Close()
		return nil, fmt.Errorf("source is not an approved regular file/directory")
	}
	return f, nil
}

type Session struct {
	config      *os.File
	read, write *os.File
	sources     []*os.File
}

func Prepare(c Config) (*Session, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	s := &Session{}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	var err error
	// Unlink the config immediately: no persistent secret-bearing config and no
	// dependence on a pipe buffer fitting the entire configuration.
	s.config, err = os.CreateTemp(filepath.Dir(c.Rootfs), ".agentguard-config-")
	if err != nil {
		return nil, err
	}
	if err = os.Remove(s.config.Name()); err != nil {
		return nil, err
	}
	if err = writeFrame(s.config, c, MaxConfigSize); err != nil {
		return nil, err
	}
	if _, err = s.config.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	for _, f := range c.Files {
		source, err := openSource(f.Source, false)
		if err != nil {
			return nil, fmt.Errorf("open approved tool: %w", err)
		}
		s.sources = append(s.sources, source)
	}
	for _, m := range c.Mounts {
		source, err := openSource(m.Source, true)
		if err != nil {
			return nil, fmt.Errorf("open approved directory: %w", err)
		}
		s.sources = append(s.sources, source)
	}
	s.read, s.write, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	ok = true
	return s, nil
}

func (s *Session) ExtraFiles() []*os.File {
	return append([]*os.File{s.config, s.write}, s.sources...)
}

// Started closes the host's copies of all child endpoints and source handles.
func (s *Session) Started(int) error {
	if s.config != nil {
		s.config.Close()
		s.config = nil
	}
	if s.write != nil {
		s.write.Close()
		s.write = nil
	}
	for _, f := range s.sources {
		f.Close()
	}
	s.sources = nil
	return nil
}

func (s *Session) readContext(ctx context.Context) (Message, error) {
	stop := context.AfterFunc(ctx, func() { s.read.Close() })
	defer stop()
	m, err := ReadMessage(s.read)
	if ctx.Err() != nil {
		return m, ctx.Err()
	}
	return m, err
}

func (s *Session) WaitReady(ctx context.Context) error {
	m, err := s.readContext(ctx)
	if err != nil {
		return &Failure{Stage: "protocol", Reason: "missing or malformed READY"}
	}
	if m.Type == "ERROR" {
		return messageError(m)
	}
	if m.Type != "READY" {
		return &Failure{Stage: "protocol", Reason: "expected READY"}
	}
	return nil
}

func (s *Session) WaitResult(ctx context.Context) (int, error) {
	m, err := s.readContext(ctx)
	if err != nil {
		return -1, &Failure{Stage: "protocol", Reason: "missing or malformed EXIT"}
	}
	if m.Type == "ERROR" {
		return -1, messageError(m)
	}
	if m.Type != "EXIT" {
		return -1, &Failure{Stage: "protocol", Reason: "expected EXIT"}
	}
	return *m.ExitCode, nil
}

func (s *Session) Close() {
	s.Started(0)
	if s.read != nil {
		s.read.Close()
	}
}
