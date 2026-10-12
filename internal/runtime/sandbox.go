package runtime

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/runtime/sandbox/linux"
	"github.com/Oreki0504/AgentGuard/internal/workload"
)

// SandboxConfig is trusted operator configuration, not Workload input. A nil
// Sandbox selects the existing direct execution mode, explicitly at Runtime
// construction. Sandbox errors never fall back to direct execution.
type SandboxConfig struct {
	Launcher       string
	RootfsBase     string
	StartupTimeout time.Duration
	Files          []linux.File
	Mounts         []linux.BindMount
}

func validateLauncher(name string) error {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return fmt.Errorf("launcher must have a clean absolute path")
	}
	for p := name; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("inspect trusted launcher: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("launcher and ancestors must be root-owned and not group/world writable")
		}
		if p == name && (!info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0) {
			return fmt.Errorf("launcher must be a regular, non-setuid executable")
		}
		if p == "/" {
			break
		}
	}
	return nil
}

func (s SandboxConfig) launchConfig(w *workload.Workload, rootfs string) linux.Config {
	spec := w.Spec()
	dir := spec.WorkingDir
	if dir == "" {
		dir = "/"
	}
	return linux.Config{Version: linux.Version, WorkloadID: w.ID(),
		Argv: append([]string{spec.Command}, spec.Args...), Env: append([]string{}, spec.Env...),
		WorkingDir: dir, Rootfs: rootfs, StartupTimeout: s.StartupTimeout,
		Files: append([]linux.File(nil), s.Files...), Mounts: append([]linux.BindMount(nil), s.Mounts...)}
}
