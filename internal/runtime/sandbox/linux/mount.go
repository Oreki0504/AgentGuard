package linux

import (
	"fmt"
	"syscall"
)

func makePrivate() error {
	return syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")
}

func bindDirectory(source, target string, readOnly bool) error {
	if err := syscall.Mount(
		source, target, "", syscall.MS_BIND, "",
	); err != nil {
		return fmt.Errorf(
			"initial MS_BIND source=%q target=%q: %w",
			source, target, err,
		)
	}

	flags := uintptr(
		syscall.MS_BIND |
			syscall.MS_REMOUNT |
			syscall.MS_NOSUID |
			syscall.MS_NODEV |
			syscall.MS_NOEXEC,
	)

	if readOnly {
		flags |= syscall.MS_RDONLY
	}

	if err := syscall.Mount(
		"", target, "", flags, "",
	); err != nil {
		return fmt.Errorf(
			"bind MS_REMOUNT target=%q: %w",
			target, err,
		)
	}

	return nil
}
