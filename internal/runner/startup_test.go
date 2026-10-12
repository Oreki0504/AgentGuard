package runner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

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
