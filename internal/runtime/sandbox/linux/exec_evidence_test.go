package linux

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func stopped(signal syscall.Signal, event int) syscall.WaitStatus {
	return syscall.WaitStatus(0x7f | int(signal)<<8 | event<<16)
}

func TestGuestReadinessRequiresExecAndDetach(t *testing.T) {
	for _, mode := range []string{
		"success", "exit-before-bootstrap", "initial-event", "initial-signal",
		"wrong-pid", "lost-child", "setoptions", "continue", "exit-before-guest",
		"plain-trap", "other-event", "other-signal", "event-query", "former-tid",
		"detach", "timeout", "cancel-before", "cancel-before-detach", "cancel-after-detach", "ready-write",
	} {
		t.Run(mode, func(t *testing.T) {
			const pid = 4321
			events := []syscall.WaitStatus{
				stopped(syscall.SIGTRAP, 0), stopped(syscall.SIGTRAP, syscall.PTRACE_EVENT_EXEC),
			}
			signals := make(chan os.Signal, 1)
			deadline := time.Now().Add(time.Second)
			switch mode {
			case "exit-before-bootstrap":
				events[0] = 0
			case "initial-event":
				events[0] = events[1]
			case "initial-signal":
				events[0] = stopped(syscall.SIGSTOP, 0)
			case "exit-before-guest":
				events[1] = 125 << 8
			case "plain-trap":
				events[1] = events[0]
			case "other-event":
				events[1] = stopped(syscall.SIGTRAP, syscall.PTRACE_EVENT_FORK)
			case "other-signal":
				events[1] = stopped(syscall.SIGSTOP, 0)
			case "timeout":
				deadline = time.Now().Add(-time.Second)
			case "cancel-before":
				signals <- syscall.SIGTERM
			}
			waits, options, resumes, detaches := 0, 0, 0, 0
			ops := traceOps{
				wait: func(want int, status *syscall.WaitStatus, flags int, _ *syscall.Rusage) (int, error) {
					if want != pid || flags != syscall.WNOHANG|syscall.WALL|waitOwnThread {
						t.Fatal("wait4 was not bound to the sole tracer and expected PID")
					}
					if mode == "lost-child" {
						return 0, syscall.ECHILD
					}
					if waits >= len(events) {
						t.Fatal("unexpected extra wait")
					}
					*status = events[waits]
					waits++
					if mode == "wrong-pid" {
						return pid + 1, nil
					}
					return pid, nil
				},
				options: func(got, flags int) error {
					options++
					if got != pid || flags != syscall.PTRACE_O_TRACEEXEC|ptraceExitKill {
						t.Fatal("wrong trace options")
					}
					if mode == "setoptions" {
						return syscall.EPERM
					}
					return nil
				},
				resume: func(got, signal int) error {
					resumes++
					if got != pid || signal != 0 {
						t.Fatal("wrong bootstrap CONT")
					}
					if mode == "continue" {
						return syscall.ESRCH
					}
					return nil
				},
				event: func(got int) (uint, error) {
					if got != pid {
						t.Fatal("event query PID mismatch")
					}
					if mode == "event-query" {
						return 0, syscall.EIO
					}
					if mode == "former-tid" {
						return pid + 1, nil
					}
					if mode == "cancel-before-detach" {
						signals <- syscall.SIGTERM
					}
					return pid, nil
				},
				detach: func(got int) error {
					detaches++
					if got != pid {
						t.Fatal("detach PID mismatch")
					}
					if mode == "detach" {
						return syscall.ESRCH
					}
					if mode == "cancel-after-detach" {
						signals <- syscall.SIGTERM
					}
					return nil
				},
			}
			status := &checkedReadyWriter{beforeWrite: func() error {
				if waits != 2 || options != 1 || resumes != 1 || detaches != 1 {
					t.Fatal("READY written before complete exec/resume evidence")
				}
				if mode == "ready-write" {
					return syscall.EPIPE
				}
				return nil
			}}
			err := confirmGuestReady(pid, deadline, signals, status, ops)
			if mode == "success" {
				if err != nil || waits != 2 || options != 1 || resumes != 1 || detaches != 1 {
					t.Fatalf("incomplete successful evidence: err=%v waits=%d options=%d resumes=%d detaches=%d",
						err, waits, options, resumes, detaches)
				}
				message, readErr := ReadMessage(&status.Buffer)
				if readErr != nil || message.Type != "READY" || status.Len() != 0 {
					t.Fatalf("expected exactly one READY: %+v %v", message, readErr)
				}
			} else if err == nil || status.Len() != 0 {
				t.Fatal("failed startup produced successful readiness")
			}
		})
	}
}

// Real unprivileged ptrace control. This does not establish the AppArmor,
// pivot_root, capability-drop or PID-namespace feasibility gate.
func TestExecEvidenceKernelControl(t *testing.T) {
	for _, test := range []struct {
		name, command string
		success       bool
	}{
		{"exec-and-immediate-exit", "exec /bin/true", true},
		{"exec-failure", "exec /no-such-agentguard-guest", false},
		{"bootstrap-exit-zero", "exit 0", false},
		{"unexpected-stop", "kill -STOP $$", false},
		{"deadline", "while :; do :; done", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer null.Close()
			process, err := os.StartProcess("/bin/sh", []string{"/bin/sh", "-c", test.command}, &os.ProcAttr{
				Env: []string{}, Files: []*os.File{null, null, null},
				Sys: &syscall.SysProcAttr{Ptrace: true},
			})
			if err != nil {
				t.Fatalf("unprivileged ptrace control unavailable: %v", err)
			}
			pid := process.Pid
			process.Release()
			ops := kernelTraceOps()
			actualWait := ops.wait
			reaped := false
			ops.wait = func(pid int, status *syscall.WaitStatus, flags int, usage *syscall.Rusage) (int, error) {
				got, err := actualWait(pid, status, flags, usage)
				if got == pid && (status.Exited() || status.Signaled()) {
					reaped = true
				}
				return got, err
			}
			defer func() {
				// Same locked thread remains the only reaper on every branch.
				// Once reaped, the PID can be reused: never signal it again.
				if reaped {
					return
				}
				_ = syscall.Kill(pid, syscall.SIGKILL)
				for {
					var status syscall.WaitStatus
					_, err := syscall.Wait4(pid, &status, syscall.WALL|waitOwnThread, nil)
					if errors.Is(err, syscall.EINTR) {
						continue
					}
					if errors.Is(err, syscall.ECHILD) {
						break
					}
					if err != nil {
						t.Errorf("tracee cleanup: %v", err)
						break
					}
					if status.Exited() || status.Signaled() {
						break
					}
					_ = syscall.PtraceCont(pid, int(syscall.SIGKILL))
				}
			}()
			deadline := time.Now().Add(time.Second)
			if test.name == "deadline" {
				deadline = time.Now().Add(30 * time.Millisecond)
			}
			err = observeGuestExec(pid, deadline, nil, ops)
			if test.success != (err == nil) {
				t.Fatalf("success=%t error=%v", test.success, err)
			}
		})
	}
}

// A status writer also checks the exact point at which READY becomes observable.
type checkedReadyWriter struct {
	bytes.Buffer
	beforeWrite func() error
}

func (w *checkedReadyWriter) Write(p []byte) (int, error) {
	if err := w.beforeWrite(); err != nil {
		return 0, err
	}
	return w.Buffer.Write(p)
}
