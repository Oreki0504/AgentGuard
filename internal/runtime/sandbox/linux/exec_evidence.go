package linux

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"
)

const (
	ptraceExitKill = 0x00100000
	waitOwnThread  = 0x20000000 // __WNOTHREAD: this locked tracer thread owns wait4.
)

type traceOps struct {
	wait    func(int, *syscall.WaitStatus, int, *syscall.Rusage) (int, error)
	options func(int, int) error
	resume  func(int, int) error
	event   func(int) (uint, error)
	detach  func(int) error
}

func kernelTraceOps() traceOps {
	return traceOps{syscall.Wait4, syscall.PtraceSetOptions, syscall.PtraceCont,
		syscall.PtraceGetEventMsg, syscall.PtraceDetach}
}

// Caller locks its OS thread BEFORE starting Bootstrap with Ptrace:true and
// remains the sole reaper. Only expected Guest EXEC and successful DETACH can
// emit the one READY. Failures require caller cleanup, with no weaker fallback.
func confirmGuestReady(pid int, deadline time.Time, signals <-chan os.Signal, status io.Writer, ops traceOps) error {
	if err := observeGuestExec(pid, deadline, signals, ops); err != nil {
		return err
	}
	return WriteMessage(status, Message{Version: Version, Type: "READY"})
}

func startupPending(deadline time.Time, signals <-chan os.Signal) error {
	for {
		if !time.Now().Before(deadline) {
			return fmt.Errorf("guest exec confirmation timed out")
		}
		select {
		case signal, open := <-signals:
			if !open || signal != syscall.SIGCHLD {
				return fmt.Errorf("guest exec confirmation canceled")
			}
		default:
			return nil
		}
	}
}

func waitTraceStop(pid int, deadline time.Time, signals <-chan os.Signal, ops traceOps) (syscall.WaitStatus, error) {
	for {
		if err := startupPending(deadline, signals); err != nil {
			return 0, err
		}
		var status syscall.WaitStatus
		child, err := ops.wait(pid, &status, syscall.WNOHANG|syscall.WALL|waitOwnThread, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("wait for traced bootstrap: %w", err)
		}
		if child == 0 {
			// Only this thread calls wait4. SIGCHLD is a wakeup hint, never
			// evidence that the expected Guest executed.
			time.Sleep(time.Millisecond)
			continue
		}
		if child != pid || !status.Stopped() {
			return 0, fmt.Errorf("bootstrap exited or unexpected wait source/status")
		}
		return status, nil
	}
}

func observeGuestExec(pid int, deadline time.Time, signals <-chan os.Signal, ops traceOps) error {
	if pid <= 0 {
		return fmt.Errorf("invalid tracee PID")
	}
	// Ptrace:true stops at Bootstrap's initial exec BEFORE main/Cx validation.
	// It is a plain SIGTRAP: TRACEEXEC has not been enabled yet.
	initial, err := waitTraceStop(pid, deadline, signals, ops)
	if err != nil {
		return err
	}
	if initial.StopSignal() != syscall.SIGTRAP || initial.TrapCause() != 0 {
		return fmt.Errorf("unexpected initial bootstrap exec stop")
	}
	if err := startupPending(deadline, signals); err != nil {
		return err
	}
	if err := ops.options(pid, syscall.PTRACE_O_TRACEEXEC|ptraceExitKill); err != nil {
		return fmt.Errorf("enable guest exec tracing: %w", err)
	}
	if err := ops.resume(pid, 0); err != nil {
		return fmt.Errorf("resume bootstrap: %w", err)
	}
	event, err := waitTraceStop(pid, deadline, signals, ops)
	if err != nil {
		return err
	}
	if event.StopSignal() != syscall.SIGTRAP || event.TrapCause() != syscall.PTRACE_EVENT_EXEC {
		return fmt.Errorf("unexpected event before guest exec")
	}
	// Bootstrap is single-threaded. A different former TID is not the expected
	// bootstrap-to-Guest transition, even if wait4 reports the thread-group PID.
	formerTID, err := ops.event(pid)
	if err != nil || formerTID != uint(pid) {
		return fmt.Errorf("guest exec event identity mismatch")
	}
	if err := startupPending(deadline, signals); err != nil {
		return err
	}
	if err := ops.detach(pid); err != nil {
		return fmt.Errorf("resume and detach guest: %w", err)
	}
	// Only successful DETACH from the validated exec stop permits READY later.
	// Guest may immediately exit; continued liveness is not a Running guarantee.
	return startupPending(deadline, signals)
}
