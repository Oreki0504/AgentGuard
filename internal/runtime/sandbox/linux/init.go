package linux

import (
	"errors"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

func prctl(option, arg uintptr) error {
	_, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, option, arg, 0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// A narrow Phase 2B prerequisite: guest exec cannot reacquire mount authority
// via UID 0 or file capabilities. Full syscall/profile policy remains Phase 2C.
// The caller must keep the OS thread locked through StartProcess: Linux
// capabilities and securebits are thread-local.
func dropMountAuthority() error {
	// Disable root's implicit exec capabilities, and lock that setting.
	if err := prctl(28 /* PR_SET_SECUREBITS */, 3 /* NOROOT | NOROOT_LOCKED */); err != nil {
		return err
	}
	for capability := uintptr(0); capability < 64; capability++ {
		err := prctl(24 /* PR_CAPBSET_DROP */, capability)
		if errors.Is(err, syscall.EINVAL) {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := prctl(47 /* PR_CAP_AMBIENT */, 4 /* CLEAR_ALL */); err != nil {
		return err
	}
	header := struct {
		Version uint32
		PID     int32
	}{Version: 0x20080522}
	data := [2]struct{ Effective, Permitted, Inheritable uint32 }{}
	_, _, errno := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func runInit(c Config, sources []*os.File, status *os.File) int {
	runtime.LockOSThread()
	// Do not unlock: privileged Go runtime threads must never be selected for
	// the guest fork, and /proc/1/fd must not expose the trusted status channel.
	if err := prctl(4 /* PR_SET_DUMPABLE */, 0); err != nil {
		return reportFailure(status, "privilege", "cannot protect init descriptors")
	}
	if err := prepareRootfs(c, sources); err != nil {
		return reportFailure(status, "rootfs", "cannot establish guest filesystem")
	}
	if err := dropMountAuthority(); err != nil {
		return reportFailure(status, "privilege", "cannot remove mount authority")
	}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	process, err := os.StartProcess(c.Argv[0], c.Argv, &os.ProcAttr{
		Dir: c.WorkingDir, Env: append([]string{}, c.Env...),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys:   &syscall.SysProcAttr{Setpgid: true},
	})
	if err != nil {
		return reportFailure(status, "exec", "cannot start requested command")
	}
	pid := process.Pid
	// wait4 below is the sole reaper, including adopted children.
	_ = process.Release()
	if err := WriteMessage(status, Message{Version: Version, Type: "READY"}); err != nil {
		return 125
	}
	mainExited := false
	code := 0
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		for {
			var ws syscall.WaitStatus
			child, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			if errors.Is(err, syscall.ECHILD) {
				if !mainExited {
					return reportFailure(status, "init", "lost main process status")
				}
				if err := WriteMessage(status, Message{Version: Version, Type: "EXIT", ExitCode: &code}); err != nil {
					return 125
				}
				return 0
			}
			if err != nil {
				return reportFailure(status, "init", "child reaping failed")
			}
			if child == 0 {
				break
			}
			if child == pid {
				mainExited = true
				code = ws.ExitStatus()
				if ws.Signaled() {
					code = 128 + int(ws.Signal())
				}
			}
		}
		select {
		case s := <-signals:
			if s != syscall.SIGCHLD {
				// PID namespace limits -1 to this workload and excludes init.
				_ = syscall.Kill(-1, s.(syscall.Signal))
			}
		case <-ticker.C:
		}
	}
}
