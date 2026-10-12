package linux

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func prepareRootfs(c Config, sources []*os.File) error {
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
	for i, file := range c.Files {
		target := filepath.Join(c.Rootfs, file.Target)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(f, io.LimitReader(sources[i], 32*1024*1024+1))
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
	}
	for i, m := range c.Mounts {
		target := filepath.Join(c.Rootfs, m.Target)
		if err := os.MkdirAll(target, 0700); err != nil {
			return err
		}
		if err := bindDirectory(sourcePath(len(c.Files)+i), target, m.ReadOnly); err != nil {
			return err
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
		if err := source.Close(); err != nil {
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
	return os.Remove("/.oldroot")
}
