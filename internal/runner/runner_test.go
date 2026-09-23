package runner

import (
	"strings"
	"testing"
)

func TestRunEcho(t *testing.T) {
	result, err := Run(Request{
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
	result, err := Run(Request{
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
	result, err := Run(Request{
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

	result, err := Run(Request{
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
