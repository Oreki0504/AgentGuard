package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/workload"
)

func TestRequestFromSpec(t *testing.T) {
	spec := workload.Spec{
		Command:    "echo",
		Args:       []string{"hello"},
		WorkingDir: "/tmp",
		Env:        []string{"KEY=value"},
		Timeout:    5 * time.Second,
	}

	req := requestFromSpec(spec)

	if req.Command != spec.Command {
		t.Fatalf("unexpected command: got %q, want %q", req.Command, spec.Command)
	}

	if len(req.Args) != 1 || req.Args[0] != "hello" {
		t.Fatalf("unexpected args: %v", req.Args)
	}

	if req.WorkingDir != spec.WorkingDir {
		t.Fatalf(
			"unexpected working directory: got %q, want %q",
			req.WorkingDir,
			spec.WorkingDir,
		)
	}

	if len(req.Env) != 1 || req.Env[0] != "KEY=value" {
		t.Fatalf("unexpected env: %v", req.Env)
	}

	if req.Timeout != spec.Timeout {
		t.Fatalf(
			"unexpected timeout: got %v, want %v",
			req.Timeout,
			spec.Timeout,
		)
	}
}

func TestRunWorkload(t *testing.T) {
	w, err := workload.New(
		"test-workload",
		workload.Spec{
			Command: "echo",
			Args:    []string{"hello"},
		},
	)
	if err != nil {
		t.Fatalf("failed to create workload: %v", err)
	}

	result, err := Run(context.Background(), w)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.Stdout != "hello\n" {
		t.Fatalf(
			"unexpected stdout: got %q, want %q",
			result.Stdout,
			"hello\n",
		)
	}

	if result.ExitCode != 0 {
		t.Fatalf(
			"unexpected exit code: got %d, want 0",
			result.ExitCode,
		)
	}

	if w.State() != workload.StateFinished {
		t.Fatalf(
			"unexpected workload state: got %q, want %q",
			w.State(),
			workload.StateFinished,
		)
	}

	if w.StartedAt().IsZero() {
		t.Fatal("expected StartedAt to be set")
	}

	if w.FinishedAt().IsZero() {
		t.Fatal("expected FinishedAt to be set")
	}
}

func TestRunWorkloadNonZeroExit(t *testing.T) {
	w, err := workload.New(
		"test-workload",
		workload.Spec{
			Command: "/bin/sh",
			Args:    []string{"-c", "exit 42"},
		},
	)
	if err != nil {
		t.Fatalf("failed to create workload: %v", err)
	}

	result, err := Run(context.Background(), w)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.ExitCode != 42 {
		t.Fatalf(
			"unexpected exit code: got %d, want 42",
			result.ExitCode,
		)
	}

	if w.State() != workload.StateFinished {
		t.Fatalf(
			"unexpected workload state: got %q, want %q",
			w.State(),
			workload.StateFinished,
		)
	}
}

func TestRunWorkloadTimeout(t *testing.T) {
	w, err := workload.New(
		"test-workload",
		workload.Spec{
			Command: "/bin/sh",
			Args:    []string{"-c", "sleep 10"},
			Timeout: 100 * time.Millisecond,
		},
	)
	if err != nil {
		t.Fatalf("failed to create workload: %v", err)
	}

	result, err := Run(context.Background(), w)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !result.TimedOut {
		t.Fatal("expected workload to time out")
	}

	if w.State() != workload.StateFailed {
		t.Fatalf(
			"unexpected workload state: got %q, want %q",
			w.State(),
			workload.StateFailed,
		)
	}

	if w.StartedAt().IsZero() {
		t.Fatal("expected StartedAt to be set")
	}

	if w.FinishedAt().IsZero() {
		t.Fatal("expected FinishedAt to be set")
	}
}
