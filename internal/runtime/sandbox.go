package runtime

import (
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
	return linux.ValidateTrustedExecutable(name)
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
