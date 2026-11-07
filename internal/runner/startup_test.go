package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

func TestStartupFailurePreservesOutputTruncation(t *testing.T) {
	for _, excess := range []int{0, 1} {
		t.Run(fmt.Sprintf("excess-%d", excess), func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			failure := errors.New("bootstrap rejected input")
			ready := false
			// The independent status FD is written after both output streams.
			// Waiting on it avoids a race between rejection and output capture.
			script := fmt.Sprintf("/usr/bin/head -c %d /dev/zero; /usr/bin/head -c %d /dev/zero >&2; printf x >&3", maxCapturedOutputBytes+excess, maxCapturedOutputBytes+excess)
			result, err := Run(context.Background(), Request{
				Command: "/bin/sh", Args: []string{"-c", script}, ExtraFiles: []*os.File{w},
				Startup: &Startup{Timeout: 3 * time.Second, Wait: func(ctx context.Context) error {
					stop := context.AfterFunc(ctx, func() { r.Close() })
					defer stop()
					var status [1]byte
					if _, err := io.ReadFull(r, status[:]); err != nil {
						return err
					}
					return failure
				}},
				Hooks: Hooks{OnStarted: func(int) error { return w.Close() }, OnReady: func(int) error { ready = true; return nil }},
			})
			if !errors.Is(err, failure) || ready || result.ExitCode != -1 ||
				len(result.Stdout) != maxCapturedOutputBytes || len(result.Stderr) != maxCapturedOutputBytes ||
				result.StdoutTruncated != (excess != 0) || result.StderrTruncated != (excess != 0) {
				t.Fatalf("err=%v ready=%t exit=%d stdout=%d/%t stderr=%d/%t", err, ready, result.ExitCode,
					len(result.Stdout), result.StdoutTruncated, len(result.Stderr), result.StderrTruncated)
			}
		})
	}
}

func TestStartupFailureNeverCallsReady(t *testing.T) {
	for _, mode := range []string{"early-exit", "error", "timeout", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := false
			terminated := false
			script := "exit 0"
			if mode == "timeout" || mode == "cancel" {
				script = "exec /bin/sleep 10"
			}
			start := time.Now()
			result, err := Run(ctx, Request{Command: "/bin/sh", Args: []string{"-c", script}, ExtraFiles: []*os.File{w},
				Startup: &Startup{Timeout: 100 * time.Millisecond, Wait: func(ctx context.Context) error {
					if mode == "error" {
						return errors.New("setup failed")
					}
					stop := context.AfterFunc(ctx, func() { r.Close() })
					defer stop()
					b := make([]byte, 1)
					_, err := r.Read(b)
					return err
				}}, Hooks: Hooks{OnStarted: func(int) error {
					w.Close()
					if mode == "cancel" {
						cancel()
					}
					return nil
				}, OnReady: func(int) error { ready = true; return nil }, OnTerminating: func(TerminationReason) error { terminated = true; return nil }}})
			if err == nil || ready || !terminated {
				t.Fatalf("err=%v ready=%v terminated=%v", err, ready, terminated)
			}
			if time.Since(start) > time.Second {
				t.Fatal("startup failure was not bounded")
			}
			if mode == "early-exit" && time.Since(start) > 80*time.Millisecond {
				t.Fatal("EOF was not detected promptly")
			}
			if mode == "cancel" && !result.Canceled {
				t.Fatal("cancellation lost")
			}
		})
	}
}

func TestStartupReadyHookAndFastNonzeroExit(t *testing.T) {
	started, ready := false, false
	result, err := Run(context.Background(), Request{Command: "/bin/sh", Args: []string{"-c", "exit 42"},
		Startup: &Startup{Timeout: time.Second, Wait: func(context.Context) error {
			if !started {
				t.Fatal("wait before started")
			}
			return nil
		}},
		Hooks: Hooks{OnStarted: func(int) error { started = true; return nil }, OnReady: func(int) error { ready = true; return nil }}})
	if err != nil || !ready || result.ExitCode != 42 {
		t.Fatalf("result=%+v ready=%v err=%v", result, ready, err)
	}
}

// A late success from the status waiter cannot override a startup deadline or
// cancellation that has already occurred before OnReady.
func TestStartupLateReadyCannotOverrideCancellation(t *testing.T) {
	for _, mode := range []string{"deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := 0
			result, err := Run(ctx, Request{Command: "/bin/sh", Args: []string{"-c", "exec /bin/sleep 10"},
				Startup: &Startup{Timeout: 25 * time.Millisecond, Wait: func(start context.Context) error {
					if mode == "cancel" {
						cancel()
					}
					<-start.Done()
					return nil
				}}, Hooks: Hooks{OnReady: func(int) error { ready++; return nil }}})
			if err == nil || ready != 0 || (mode == "deadline" && !result.TimedOut) || (mode == "cancel" && !result.Canceled) {
				t.Fatalf("ready=%d result=%+v err=%v", ready, result, err)
			}
		})
	}
}
