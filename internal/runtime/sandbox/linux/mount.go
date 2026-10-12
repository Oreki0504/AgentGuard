package linux

import "syscall"

func makePrivate() error {
	return syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")
}

func bindDirectory(source, target string, readOnly bool) error {
	// Deliberately non-recursive: nested host mounts are not authorized by a
	// parent directory exposure and cannot hide writable child mounts.
	if err := syscall.Mount(source, target, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	flags := uintptr(syscall.MS_BIND | syscall.MS_REMOUNT | syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC)
	if readOnly {
		flags |= syscall.MS_RDONLY
	}
	return syscall.Mount("", target, "", flags, "")
}
