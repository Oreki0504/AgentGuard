package linux

import (
	"fmt"
	"syscall"
)

// rebindBootstrapNullStdio runs after pivot_root and old-root detach, while
// PID1 is still in the parent profile. Its existing /dev/null rule authorizes
// reopening the private bind. The parent already uses attach_disconnected for
// its inherited host descriptors; the Workload profile does not. Rebind before
// Cx so Guest stdio refers to the connected private mount. Pipes and regular
// files retain their original descriptions.
func rebindBootstrapNullStdio(privateNull string) error {
	var target syscall.Stat_t
	if err := syscall.Lstat(privateNull, &target); err != nil {
		return fmt.Errorf("inspect private null device: %w", err)
	}
	// Linux /dev/null is character device major 1, minor 3.
	if target.Mode&syscall.S_IFMT != syscall.S_IFCHR || target.Rdev != 0x103 {
		return fmt.Errorf("private null target is not /dev/null")
	}
	for fd := 0; fd <= 2; fd++ {
		var original syscall.Stat_t
		if err := syscall.Fstat(fd, &original); err != nil {
			return fmt.Errorf("inspect standard stream %d: %w", fd, err)
		}
		if original.Mode&syscall.S_IFMT != syscall.S_IFCHR {
			continue
		}
		if original.Rdev != target.Rdev {
			return fmt.Errorf("unapproved standard-stream device %d", fd)
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
		if errno != 0 {
			return fmt.Errorf("inspect standard-stream access %d: %w", fd, errno)
		}
		descriptorFlags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != 0 || descriptorFlags&syscall.FD_CLOEXEC != 0 || flags&oPath != 0 {
			return fmt.Errorf("invalid standard-stream descriptor %d", fd)
		}
		access := int(flags) & syscall.O_ACCMODE
		expected := syscall.O_WRONLY
		if fd == 0 {
			expected = syscall.O_RDONLY
		}
		if access != expected && access != syscall.O_RDWR {
			return fmt.Errorf("invalid standard-stream access %d", fd)
		}
		reopened, err := syscall.Open(privateNull, access|int(flags)&syscall.O_NONBLOCK|
			syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("reopen private null for stream %d: %w", fd, err)
		}
		var actual syscall.Stat_t
		statErr := syscall.Fstat(reopened, &actual)
		if statErr != nil || actual.Mode&syscall.S_IFMT != syscall.S_IFCHR ||
			actual.Rdev != target.Rdev || actual.Dev != target.Dev || actual.Ino != target.Ino {
			syscall.Close(reopened)
			return fmt.Errorf("private null changed before reopen for stream %d", fd)
		}
		dupErr := syscall.Dup3(reopened, fd, 0)
		closeErr := syscall.Close(reopened)
		_, _, closed := syscall.Syscall(syscall.SYS_FCNTL, uintptr(reopened), syscall.F_GETFD, 0)
		if dupErr != nil || closeErr != nil || closed != syscall.EBADF {
			return fmt.Errorf("rebind stream %d: dup=%v close=%v closure=%v", fd, dupErr, closeErr, closed)
		}
		var rebound syscall.Stat_t
		if err := syscall.Fstat(fd, &rebound); err != nil ||
			rebound.Dev != actual.Dev || rebound.Ino != actual.Ino || rebound.Rdev != actual.Rdev {
			return fmt.Errorf("standard stream %d rebind not confirmed", fd)
		}
	}
	return nil
}
