package linux

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// The Bootstrap source is pinned by Runtime and checked against the installed
// image before namespace rootfs preparation. No direct-Guest layout is exposed.
func prepareBootstrapRootfs(c Config, sources []*os.File, bootstrap *os.File) error {
	if bootstrap == nil {
		return fmt.Errorf("missing trusted bootstrap")
	}
	if err := validateBootstrapConfig(c); err != nil {
		return err
	}
	return prepareRootfsLayout(c, sources, bootstrap)
}

func prepareRootfsLayout(c Config, sources []*os.File, bootstrap *os.File) error {
	if len(sources) != len(c.Files)+len(c.Mounts) {
		return fmt.Errorf("incorrect source descriptor count")
	}
	info, err := os.Lstat(c.Rootfs)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return fmt.Errorf("rootfs must be a private directory")
	}
	entries, err := os.ReadDir(c.Rootfs)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("rootfs must be empty")
	}
	if err := makePrivate(); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", c.Rootfs, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=64m,mode=0700"); err != nil {
		return err
	}
	for _, dir := range []string{"proc", "dev", "tmp", ".oldroot"} {
		if err := os.Mkdir(filepath.Join(c.Rootfs, dir), 0700); err != nil {
			return err
		}
	}
	if bootstrap != nil {
		if err := os.Mkdir(filepath.Join(c.Rootfs, ".agentguard"), 0755); err != nil {
			return err
		}
		if err := copyApprovedFile(bootstrap, filepath.Join(c.Rootfs, bootstrapEntry)); err != nil {
			return err
		}
		if err := mountBootstrapWritableAreas(c); err != nil {
			return err
		}
	}
	for i, file := range c.Files {
		target := filepath.Join(c.Rootfs, file.Target)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := copyApprovedFile(sources[i], target); err != nil {
			return err
		}
	}
	for i, m := range c.Mounts {
		target := filepath.Join(c.Rootfs, m.Target)
		if err := os.MkdirAll(target, 0700); err != nil {
			return err
		}
		if err := bindVerifiedDirectory(
			sources[len(c.Files)+i],
			m,
			target,
			bootstrap != nil,
		); err != nil {
			return fmt.Errorf(
				"bind mount target=%q readonly=%t: %w",
				m.Target,
				m.ReadOnly,
				err,
			)
		}
	}
	// proc is mounted only by namespace PID 1, and exposes that PID namespace.
	if err := syscall.Mount("proc", filepath.Join(c.Rootfs, "proc"), "proc", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return err
	}
	null := filepath.Join(c.Rootfs, "dev/null")
	f, err := os.OpenFile(null, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	f.Close()
	if err := syscall.Mount("/dev/null", null, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	if err := syscall.Mount("", null, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_NOSUID|syscall.MS_NOEXEC, ""); err != nil {
		return err
	}
	// Drop every host source FD before detaching the old root.
	for _, source := range sources {
		closeSource := source.Close
		if bootstrap != nil {
			closeSource = func() error { return closeVerified(source) }
		}
		if err := closeSource(); err != nil {
			return err
		}
	}
	if bootstrap != nil {
		if err := closeVerified(bootstrap); err != nil {
			return err
		}
	}
	if err := syscall.PivotRoot(c.Rootfs, filepath.Join(c.Rootfs, ".oldroot")); err != nil {
		return err
	}
	if err := os.Chdir("/"); err != nil {
		return err
	}
	if err := syscall.Unmount("/.oldroot", syscall.MNT_DETACH); err != nil {
		return err
	}
	if err := os.Remove("/.oldroot"); err != nil {
		return err
	}
	if bootstrap != nil {
		// The bound device retains host root ownership, so the parent's owner
		// rules on the staging rootfs cannot authorize reopening it there.
		// After pivot and old-root detach, use the existing /dev/null rule.
		if err := rebindBootstrapNullStdio("/dev/null"); err != nil {
			return err
		}
		if err := syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV, ""); err != nil {
			return err
		}
		return verifyBootstrapMounts(c)
	}
	return nil
}

func copyApprovedFile(source *os.File, target string) error {
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(source, 32*1024*1024+1))
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	if n > 32*1024*1024 {
		return fmt.Errorf("approved tool too large")
	}
	return nil
}

func mountBootstrapWritableAreas(c Config) error {
	workspaceBound := false
	for _, mount := range c.Mounts {
		workspaceBound = workspaceBound || mount.Target == "/workspace"
	}
	for _, target := range []string{"/tmp", "/workspace"} {
		dir := filepath.Join(c.Rootfs, target)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if target == "/workspace" && workspaceBound {
			continue
		}
		if err := syscall.Mount("tmpfs", dir, "tmpfs",
			syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "size=16m,mode=0700"); err != nil {
			return err
		}
	}
	return nil
}

func verifyBootstrapMounts(c Config) error {
	check := func(target string, readOnly, noexec bool) error {
		var fs syscall.Statfs_t
		if err := syscall.Statfs(target, &fs); err != nil {
			return err
		}
		flags := uint64(fs.Flags)
		if flags&syscall.MS_NOSUID == 0 || flags&syscall.MS_NODEV == 0 ||
			(flags&syscall.MS_RDONLY != 0) != readOnly || (flags&syscall.MS_NOEXEC != 0) != noexec {
			return fmt.Errorf("unexpected mount flags for %s", target)
		}
		return nil
	}
	if err := check("/", true, false); err != nil {
		return err
	}
	if err := check("/tmp", false, true); err != nil {
		return err
	}
	workspaceReadOnly := false
	for _, mount := range c.Mounts {
		if mount.Target == "/workspace" {
			workspaceReadOnly = mount.ReadOnly
		}
		if err := check(mount.Target, mount.ReadOnly, true); err != nil {
			return err
		}
	}
	return check("/workspace", workspaceReadOnly, true)
}

func reopenVerifiedDirectory(path string, pinned *os.File) (*os.File, error) {
	// Reopen the path inside the current mount namespace.
	current, err := openSource(path, true)
	if err != nil {
		return nil, fmt.Errorf("reopen approved directory: %w", err)
	}

	// The original FD was opened by the trusted Runtime.
	originalInfo, err := pinned.Stat()
	if err != nil {
		current.Close()
		return nil, fmt.Errorf("stat pinned directory: %w", err)
	}

	currentInfo, err := current.Stat()
	if err != nil {
		current.Close()
		return nil, fmt.Errorf("stat reopened directory: %w", err)
	}

	// Refuse to mount a different filesystem object.
	if !os.SameFile(originalInfo, currentInfo) {
		current.Close()
		return nil, fmt.Errorf("approved directory changed before mount")
	}

	return current, nil
}

func bindVerifiedDirectory(
	pinned *os.File,
	m BindMount,
	target string,
	verifyClose bool,
) (result error) {
	current, err := reopenVerifiedDirectory(m.Source, pinned)
	if err != nil {
		return err
	}
	defer func() {
		if verifyClose {
			result = errors.Join(result, closeVerified(current))
		} else {
			current.Close()
		}
	}()

	// This FD was opened in the current mount namespace.
	source := fmt.Sprintf("/proc/self/fd/%d", current.Fd())

	return bindDirectory(source, target, m.ReadOnly)
}
