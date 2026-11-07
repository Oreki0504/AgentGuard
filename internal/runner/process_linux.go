package runner

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

// waitExited observes exit without releasing the child's PID. Run is the sole
// reaper: even an exited group leader reserves its number until cmd.Wait, after
// all possible process-group signals. Hooks must not reap the direct child.
func waitExited(pid int) error {
	return waitChild(pid, syscall.WEXITED|syscall.WNOWAIT)
}

func waitChild(pid, options int) error {
	var info [16]uint64 // Aligned Linux siginfo_t; its contents are not needed here.
	for {
		_, _, errno := syscall.Syscall6(syscall.SYS_WAITID, 1 /* P_PID */, uintptr(pid),
			uintptr(unsafe.Pointer(&info[0])), uintptr(options), 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return os.NewSyscallError("waitid", errno)
		}
		return nil
	}
}

// Own the copy pipes so that draining output does not require cmd.Wait to reap
// the child first. This preserves cancellation of a group whose exited leader
// left descendants holding its pipes, as well as exec's bounded I/O wait.
type commandIO struct {
	parent []*os.File
	child  []*os.File
	copy   []func() error
}

func (s *commandIO) output(dst io.Writer) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.parent = append(s.parent, r)
	s.child = append(s.child, w)
	s.copy = append(s.copy, func() error {
		defer r.Close()
		_, err := io.Copy(dst, r)
		return err
	})
	return w, nil
}

func (s *commandIO) input(src io.Reader) (io.Reader, error) {
	if src == nil {
		return nil, nil
	}
	if file, ok := src.(*os.File); ok {
		return file, nil // Caller-owned file; no copy goroutine, as in os/exec.
	}
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.child = append(s.child, r)
	s.parent = append(s.parent, w)
	s.copy = append(s.copy, func() error {
		defer w.Close()
		_, err := io.Copy(w, src)
		if errors.Is(err, syscall.EPIPE) {
			return nil // The child is allowed to stop reading stdin early.
		}
		return err
	})
	return r, nil
}

func (s *commandIO) close() {
	for _, files := range [][]*os.File{s.parent, s.child} {
		for _, file := range files {
			_ = file.Close()
		}
	}
}

type completion struct {
	exitErr error
	ioErr   error
}

func (s *commandIO) watch(cmd *exec.Cmd) <-chan completion {
	for _, file := range s.child {
		_ = file.Close()
	}
	copied := make(chan error, len(s.copy))
	for _, copy := range s.copy {
		go func() { copied <- copy() }()
	}
	done := make(chan completion, 1)
	go func() {
		exitErr := waitExited(cmd.Process.Pid)
		if exitErr != nil {
			// An observation failure cannot authorize a numeric group signal.
			// Process.Kill uses os.Process's identity-safe signaling path.
			_ = cmd.Process.Kill()
			s.close()
		}
		timer := time.NewTimer(cmd.WaitDelay)
		defer timer.Stop()
		var ioErr error
		for range s.copy {
			select {
			case err := <-copied:
				if ioErr == nil {
					ioErr = err
				}
			case <-timer.C:
				s.close()
				<-copied
				ioErr = exec.ErrWaitDelay
			}
		}
		done <- completion{exitErr: exitErr, ioErr: ioErr}
	}()
	return done
}

func killCommand(cmd *exec.Cmd, cgroupManaged bool) {
	if cgroupManaged {
		// The owner's OnTerminating hook kills the cgroup. Only the direct
		// child needs a fallback here if that hook fails; never signal a PGID.
		_ = cmd.Process.Kill()
		return
	}
	// Confirm that the child is still waitable before using its numeric PGID.
	// No other code may reap it between this check and the signal. If waitid
	// itself fails, use only os.Process's signaling path, never a bare number.
	if waitChild(cmd.Process.Pid, syscall.WEXITED|syscall.WNOWAIT|syscall.WNOHANG) != nil {
		_ = cmd.Process.Kill()
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
