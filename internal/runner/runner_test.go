package runner

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRunEcho(t *testing.T) {
	result, err := Run(context.Background(), Request{
		Command: "echo",
		Args:    []string{"hello"},
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.Stdout != "hello\n" {
		t.Fatalf("unexpected stdout: %q", result.Stdout)
	}

	if result.Stderr != "" {
		t.Fatalf("unexpected stderr: %q", result.Stderr)
	}

	if result.ExitCode != 0 {
		t.Fatalf("unexpected exit code: %d", result.ExitCode)
	}
}

func TestRunNonZeroExit(t *testing.T) {
	result, err := Run(context.Background(), Request{
		Command: "sh",
		Args:    []string{"-c", "exit 42"},
	})

	if err != nil {
		t.Fatalf("Run returned unexpected error: %v", err)
	}

	if result.ExitCode != 42 {
		t.Fatalf("unexpected exit code: got %d, want 42", result.ExitCode)
	}
}

func TestRunCommandNotFound(t *testing.T) {
	result, err := Run(context.Background(), Request{
		Command: "definitely-not-a-real-command",
	})

	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	if result.ExitCode != -1 {
		t.Fatalf("unexpected exit code: got %d, want -1", result.ExitCode)
	}
}

func TestRunWorkingDirectory(t *testing.T) {
	dir := t.TempDir()

	result, err := Run(context.Background(), Request{
		Command:    "pwd",
		WorkingDir: dir,
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got := strings.TrimSpace(result.Stdout)

	if got != dir {
		t.Fatalf("unexpected working directory: got %q, want %q", got, dir)
	}
}
func TestRunDoesNotInheritHostEnvironment(t *testing.T) {
	t.Setenv("AGENTGUARD_SECRET", "super-secret")

	result, err := Run(context.Background(), Request{
		Command: "sh",
		Args: []string{
			"-c",
			"printf '%s' \"$AGENTGUARD_SECRET\"",
		},
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.Stdout != "" {
		t.Fatalf(
			"host environment variable was inherited: got %q",
			result.Stdout,
		)
	}
}
func TestRunDuration(t *testing.T) {
	result, err := Run(context.Background(), Request{
		Command: "sleep",
		Args:    []string{"0.1"},
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.Duration <= 0 {
		t.Fatalf("expected positive duration, got %v", result.Duration)
	}
}

func TestRunTimeout(t *testing.T) {
	result, err := Run(context.Background(), Request{
		Command: "sleep",
		Args:    []string{"10"},
		Timeout: 100 * time.Millisecond,
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !result.TimedOut {
		t.Fatal("expected command to time out")
	}

	if result.Duration >= time.Second {
		t.Fatalf("timeout took too long: %v", result.Duration)
	}
}

func TestRunCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	result, err := Run(ctx, Request{
		Command: "sleep",
		Args:    []string{"10"},
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !result.Canceled {
		t.Fatal("expected command to be canceled")
	}

	if result.Duration >= time.Second {
		t.Fatalf("cancellation took too long: %v", result.Duration)
	}
}

func TestRunKillsChildProcessesOnTimeout(t *testing.T) {
	pidFile := t.TempDir() + "/child.pid"

	result, err := Run(context.Background(), Request{
		Command: "/bin/sh",
		Args: []string{
			"-c",
			`/bin/sleep 30 & echo $! > "$1"; wait`,
			"sh",
			pidFile,
		},
		Timeout: 500 * time.Millisecond,
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !result.TimedOut {
		t.Fatal("expected command to time out")
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read child PID: %v", err)
	}

	childPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("invalid child PID: %v", err)
	}

	deadline := time.Now().Add(1 * time.Second)

	for {
		err = syscall.Kill(childPID, 0)

		if errors.Is(err, syscall.ESRCH) {
			break
		}

		if err != nil {
			t.Fatalf("unexpected error checking child process: %v", err)
		}

		statusPath := "/proc/" + strconv.Itoa(childPID) + "/status"

		status, readErr := os.ReadFile(statusPath)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				break
			}

			t.Fatalf("failed to read child process status: %v", readErr)
		}

		if strings.Contains(string(status), "State:\tZ") {
			// Zombie: process 已经退出，不能再执行代码。
			break
		}

		if time.Now().After(deadline) {
			t.Fatalf("child process %d is still running after cleanup", childPID)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunDoesNotStartWithCanceledContext(t *testing.T) {
	dir := t.TempDir()
	marker := dir + "/started"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Run(ctx, Request{
		Command: "/bin/sh",
		Args: []string{
			"-c",
			`echo started > "$1"`,
			"sh",
			marker,
		},
	})

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !result.Canceled {
		t.Fatal("expected result to be canceled")
	}

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("command appears to have started")
	}
}
