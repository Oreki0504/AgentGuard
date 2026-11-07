package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireZombie(t *testing.T, pid int) {
	t.Helper()
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatalf("child identity was released before termination: %v", err)
	}
	fields := strings.Fields(string(data)[strings.LastIndexByte(string(data), ')')+1:])
	if len(fields) == 0 || fields[0] != "Z" {
		t.Fatalf("expected exited, unreaped child %d: %s", pid, data)
	}
}

func TestCompletionDoesNotReapChild(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "printf captured; exit 42")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 500 * time.Millisecond
	streams := &commandIO{}
	defer streams.close()
	var output strings.Builder
	var err error
	cmd.Stdout, err = streams.output(&output)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	done := <-streams.watch(cmd)
	if done.exitErr != nil || done.ioErr != nil || output.String() != "captured" {
		t.Fatalf("completion=%+v output=%q", done, output.String())
	}
	// Completion is already delivered. The identity must still be reserved,
	// independent of how long the caller takes to consume that notification.
	requireZombie(t, cmd.Process.Pid)
	killCommand(cmd, false)
	if err := cmd.Wait(); err == nil || cmd.ProcessState.ExitCode() != 42 {
		t.Fatalf("wait=%v state=%v", err, cmd.ProcessState)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(cmd.Process.Pid, &status, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Fatalf("direct child was not reaped: %v", err)
	}
}

func TestStartupFailureRetainsExitedChild(t *testing.T) {
	var pid int
	failure := errors.New("rejected startup")
	terminated := false
	result, err := Run(context.Background(), Request{
		Command: "/bin/sh", Args: []string{"-c", "printf diagnostic >&2; exit 42"},
		Startup: &Startup{Timeout: time.Second, Wait: func(context.Context) error {
			if err := waitExited(pid); err != nil {
				t.Fatal(err)
			}
			return failure
		}},
		Hooks: Hooks{
			OnStarted: func(child int) error { pid = child; return nil },
			OnTerminating: func(reason TerminationReason) error {
				requireZombie(t, pid)
				terminated = true
				if reason != TerminationStartup {
					t.Fatalf("reason=%s", reason)
				}
				return nil
			},
		},
	})
	if !errors.Is(err, failure) || !terminated || result.Stderr != "diagnostic" {
		t.Fatalf("result=%+v err=%v terminated=%t", result, err, terminated)
	}
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); err != syscall.ECHILD {
		t.Fatalf("startup failure did not reap direct child: %v", err)
	}
}

func childHandle(t *testing.T, pid int) *os.Process {
	t.Helper()
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Kill(); _, _ = child.Wait(); _ = child.Release() })
	return child
}

func TestTerminationAfterLeaderExitKillsGroup(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "pipe-delay"} {
		t.Run(mode, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var leader, descendant int
			terminated := false
			req := Request{
				Command: "/bin/sh", Args: []string{"-c", `/bin/sleep 30 3>&- & printf '%s\n' "$!" >&3; exit 0`},
				ExtraFiles: []*os.File{w},
				Startup: &Startup{Timeout: 2 * time.Second, Wait: func(context.Context) error {
					if _, err := fmt.Fscanln(r, &descendant); err != nil {
						t.Fatal(err)
					}
					childHandle(t, descendant)
					if err := waitExited(leader); err != nil {
						t.Fatal(err)
					}
					return nil
				}},
				Hooks: Hooks{
					OnStarted: func(pid int) error { leader = pid; return w.Close() },
					OnReady: func(int) error {
						if mode == "cancel" {
							cancel()
						}
						return nil
					},
					OnTerminating: func(reason TerminationReason) error {
						requireZombie(t, leader)
						terminated = true
						return nil
					},
				},
			}
			if mode == "timeout" {
				req.Timeout = 200 * time.Millisecond
			}
			result, err := Run(ctx, req)
			if mode == "pipe-delay" {
				if !errors.Is(err, exec.ErrWaitDelay) || terminated || result.Duration > 2*time.Second {
					t.Fatalf("unbounded/incorrect pipe drain: result=%+v err=%v terminated=%t", result, err, terminated)
				}
				return
			}
			if err != nil || !terminated || (mode == "timeout" && !result.TimedOut) ||
				(mode == "cancel" && !result.Canceled) || result.Duration > 2*time.Second {
				t.Fatalf("result=%+v err=%v terminated=%t", result, err, terminated)
			}
			// exit_files can close the last output pipe before exit_notify
			// publishes Z. Wait for death, not merely pipe EOF or signal delivery.
			deadline := time.Now().Add(time.Second)
			for {
				data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", descendant))
				if os.IsNotExist(err) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if strings.Fields(string(data)[strings.LastIndexByte(string(data), ')')+1:])[0] == "Z" {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("descendant survived group termination: %s", data)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

func TestCgroupFallbackSignalsOnlyDirectChild(t *testing.T) {
	testGroupSignalBoundary(t, false)
}

func TestReapedChildCannotAuthorizeGroupSignal(t *testing.T) {
	testGroupSignalBoundary(t, true)
}

func testGroupSignalBoundary(t *testing.T, reapFirst bool) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	cmd := exec.Command("/bin/sh", "-c", `/bin/sleep 30 3>&- & printf '%s\n' "$!" >&3; wait`)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.ExtraFiles = []*os.File{w}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	w.Close()
	var pid int
	if _, err := fmt.Fscanln(r, &pid); err != nil {
		t.Fatal(err)
	}
	child := childHandle(t, pid)
	if reapFirst {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		// The old PGID still has a member, but the direct child's identity is
		// gone. A late call must not authorize even this numeric group signal.
		killCommand(cmd, false)
	} else {
		killCommand(cmd, true)
		if err := cmd.Wait(); err == nil {
			t.Fatal("direct child was not killed")
		}
	}
	// Give an incorrectly signaled group member time to publish its death.
	time.Sleep(50 * time.Millisecond)
	if err := child.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("fallback signaled the process group: %v", err)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil || strings.Fields(string(data)[strings.LastIndexByte(string(data), ')')+1:])[0] == "Z" {
		t.Fatalf("group member was killed: stat=%s err=%v", data, err)
	}
}

func TestRunCopiesInputAndAllowsEarlyStdinClose(t *testing.T) {
	for _, command := range []string{"/bin/cat", "/bin/true"} {
		input := strings.Repeat("input\n", 32768)
		result, err := Run(context.Background(), Request{Command: command, Stdin: strings.NewReader(input)})
		if err != nil || result.ExitCode != 0 || (command == "/bin/cat" && result.Stdout != input) {
			t.Fatalf("command=%s exit=%d output=%d err=%v", command, result.ExitCode, len(result.Stdout), err)
		}
	}
	failure := errors.New("input read failed")
	result, err := Run(context.Background(), Request{Command: "/bin/cat", Stdin: failingReader{failure}})
	if !errors.Is(err, failure) || result.ExitCode != 0 {
		t.Fatalf("input error lost: result=%+v err=%v", result, err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }
