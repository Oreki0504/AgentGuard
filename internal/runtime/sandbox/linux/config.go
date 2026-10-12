// Package linux implements the trusted Linux sandbox launcher contract.
package linux

import (
	"fmt"
	"path"
	"strings"
	"time"
)

const (
	Version               = 1
	DefaultStartupTimeout = 5 * time.Second
	MaxStartupTimeout     = 30 * time.Second
	MaxConfigSize         = 64 * 1024
)

// BindMount and File are operator-authorized host exposures, never request
// fields. Directories are always nosuid, nodev and noexec. Files are copied
// into the private tmpfs and form the approved executable/library set.
type BindMount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type File struct {
	Source string
	Target string
}

type Config struct {
	Version        int
	WorkloadID     string
	Argv           []string
	Env            []string
	WorkingDir     string
	Rootfs         string
	StartupTimeout time.Duration
	Mounts         []BindMount
	Files          []File
}

func cleanAbsolute(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsRune(p, 0)
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func (c Config) Validate() error {
	if c.Version != Version || c.WorkloadID == "" || len(c.WorkloadID) > 256 || strings.ContainsRune(c.WorkloadID, 0) {
		return fmt.Errorf("invalid protocol version or workload identity")
	}
	if len(c.Argv) == 0 || !cleanAbsolute(c.Argv[0]) || c.Argv[0] == "/" {
		return fmt.Errorf("guest executable must be an absolute, clean path")
	}
	for _, arg := range c.Argv {
		if strings.ContainsRune(arg, 0) {
			return fmt.Errorf("NUL in argument")
		}
	}
	seenEnv := map[string]bool{}
	for _, env := range c.Env {
		key, _, ok := strings.Cut(env, "=")
		if !ok || key == "" || strings.ContainsRune(env, 0) || seenEnv[key] {
			return fmt.Errorf("invalid or duplicate environment key")
		}
		seenEnv[key] = true
	}
	if !cleanAbsolute(c.WorkingDir) || !cleanAbsolute(c.Rootfs) || c.Rootfs == "/" {
		return fmt.Errorf("invalid working directory or rootfs")
	}
	if c.StartupTimeout <= 0 || c.StartupTimeout > MaxStartupTimeout {
		return fmt.Errorf("startup timeout must be positive and at most %s", MaxStartupTimeout)
	}
	if len(c.Mounts) > 32 || len(c.Files) == 0 || len(c.Files) > 32 {
		return fmt.Errorf("invalid number of filesystem exposures")
	}
	targets := []string{}
	validate := func(source, target string, directory bool) error {
		if !cleanAbsolute(source) || source == "/" || !cleanAbsolute(target) || target == "/" {
			return fmt.Errorf("exposure paths must be absolute, clean and non-root")
		}
		for _, reserved := range []string{"/proc", "/dev", "/tmp", "/.oldroot"} {
			if overlaps(target, reserved) {
				return fmt.Errorf("reserved guest target: %s", target)
			}
		}
		if directory {
			for _, reserved := range []string{"/bin", "/lib", "/lib64", "/usr"} {
				if overlaps(target, reserved) {
					return fmt.Errorf("directory overlaps guest tools: %s", target)
				}
			}
		}
		for _, previous := range targets {
			if overlaps(target, previous) {
				return fmt.Errorf("overlapping guest targets")
			}
		}
		targets = append(targets, target)
		return nil
	}
	for _, f := range c.Files {
		if err := validate(f.Source, f.Target, false); err != nil {
			return err
		}
	}
	for _, m := range c.Mounts {
		if err := validate(m.Source, m.Target, true); err != nil {
			return err
		}
	}
	return nil
}
