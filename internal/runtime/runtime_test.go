package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/audit"
	"github.com/Oreki0504/AgentGuard/internal/runner"
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

type fakeCgroupGroup struct {
	killCalled      bool
	waitEmptyCalled bool
	removeCalled    bool
}

func (g *fakeCgroupGroup) Open() (*os.File, error) {
	return os.Open(os.DevNull)
}

func (g *fakeCgroupGroup) Kill() error {
	g.killCalled = true
	return nil
}

func (g *fakeCgroupGroup) WaitEmpty(
	ctx context.Context,
) error {
	g.waitEmptyCalled = true
	return nil
}

func (g *fakeCgroupGroup) Remove() error {
	g.removeCalled = true
	return nil
}

type fakeCgroupBackend struct {
	group     *fakeCgroupGroup
	created   bool
	resources workload.ResourceSpec
}

func (b *fakeCgroupBackend) Create(
	name string,
	resources workload.ResourceSpec,
) (cgroupGroup, error) {
	b.created = true
	b.resources = resources

	return b.group, nil
}

func newTestRuntime(
	execute func(
		context.Context,
		runner.Request,
	) (runner.Result, error),
) (*Runtime, *fakeCgroupBackend, *fakeCgroupGroup) {
	group := &fakeCgroupGroup{}

	backend := &fakeCgroupBackend{
		group: group,
	}

	rt := &Runtime{
		cgroups:        backend,
		execute:        execute,
		cleanupTimeout: time.Second,
	}

	return rt, backend, group
}

func TestRuntimeRunFinishesWorkload(t *testing.T) {
	spec := workload.Spec{
		Command: "/bin/true",
		Resources: workload.ResourceSpec{
			MemoryBytes:  64 * 1024 * 1024,
			MaxProcesses: 16,
		},
	}

	w, err := workload.New("test-workload", spec)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	group := &fakeCgroupGroup{}

	backend := &fakeCgroupBackend{
		group: group,
	}

	rt := &Runtime{
		cgroups: backend,
		execute: func(
			ctx context.Context,
			req runner.Request,
		) (runner.Result, error) {
			if !req.Linux.UseCgroupFD {
				t.Fatal("expected cgroup FD to be enabled")
			}

			if req.Hooks.OnStarted == nil {
				t.Fatal("expected OnStarted hook")
			}

			if err := req.Hooks.OnStarted(1234); err != nil {
				return runner.Result{}, err
			}

			return runner.Result{
				ExitCode: 0,
			}, nil
		},
		cleanupTimeout: time.Second,
	}

	result, err := rt.Run(
		context.Background(),
		w,
	)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.ExitCode != 0 {
		t.Fatalf(
			"unexpected exit code: got %d, want 0",
			result.ExitCode,
		)
	}

	if w.State() != workload.StateFinished {
		t.Fatalf(
			"unexpected workload state: got %s, want %s",
			w.State(),
			workload.StateFinished,
		)
	}

	if !backend.created {
		t.Fatal("expected cgroup to be created")
	}

	if !group.killCalled {
		t.Fatal("expected cgroup Kill to be called")
	}

	if !group.waitEmptyCalled {
		t.Fatal("expected cgroup WaitEmpty to be called")
	}

	if !group.removeCalled {
		t.Fatal("expected cgroup Remove to be called")
	}
}

func TestRuntimeRunNonZeroExitFinishesWorkload(t *testing.T) {
	w, err := workload.New(
		"test-nonzero",
		workload.Spec{
			Command: "/bin/sh",
			Args:    []string{"-c", "exit 42"},
		},
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	group := &fakeCgroupGroup{}
	backend := &fakeCgroupBackend{
		group: group,
	}

	rt := &Runtime{
		cgroups: backend,
		execute: func(
			ctx context.Context,
			req runner.Request,
		) (runner.Result, error) {
			if err := req.Hooks.OnStarted(1234); err != nil {
				return runner.Result{}, err
			}

			return runner.Result{
				ExitCode: 42,
			}, nil
		},
		cleanupTimeout: time.Second,
	}

	result, err := rt.Run(context.Background(), w)
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
			"unexpected workload state: got %s, want %s",
			w.State(),
			workload.StateFinished,
		)
	}
}

func TestRuntimeRunTimeoutFailsWorkload(t *testing.T) {
	w, err := workload.New(
		"test-timeout",
		workload.Spec{
			Command: "/bin/sleep",
			Args:    []string{"10"},
		},
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	group := &fakeCgroupGroup{}
	backend := &fakeCgroupBackend{
		group: group,
	}

	rt := &Runtime{
		cgroups: backend,
		execute: func(
			ctx context.Context,
			req runner.Request,
		) (runner.Result, error) {
			if err := req.Hooks.OnStarted(1234); err != nil {
				return runner.Result{}, err
			}

			return runner.Result{
				ExitCode: -1,
				TimedOut: true,
			}, nil
		},
		cleanupTimeout: time.Second,
	}

	result, err := rt.Run(context.Background(), w)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !result.TimedOut {
		t.Fatal("expected result to be timed out")
	}

	if w.State() != workload.StateFailed {
		t.Fatalf(
			"unexpected workload state: got %s, want %s",
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

func TestRuntimeRunStartFailureDoesNotMarkStarted(t *testing.T) {
	w, err := workload.New(
		"test-start-failure",
		workload.Spec{
			Command: "/definitely/not/a/real/command",
		},
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	group := &fakeCgroupGroup{}
	backend := &fakeCgroupBackend{
		group: group,
	}

	rt := &Runtime{
		cgroups: backend,
		execute: func(
			ctx context.Context,
			req runner.Request,
		) (runner.Result, error) {
			// 注意：故意不调用 OnStarted。
			return runner.Result{
				ExitCode: -1,
			}, fmt.Errorf("failed to start process")
		},
		cleanupTimeout: time.Second,
	}

	_, err = rt.Run(context.Background(), w)
	if err == nil {
		t.Fatal("expected Run to return error")
	}

	if !w.StartedAt().IsZero() {
		t.Fatal("StartedAt must remain zero when process never started")
	}

	if w.State() != workload.StateFailed {
		t.Fatalf(
			"unexpected workload state: got %s, want %s",
			w.State(),
			workload.StateFailed,
		)
	}

	if !group.removeCalled {
		t.Fatal("expected cgroup to be cleaned up")
	}
}

func TestRuntimeRunRejectsNilWorkload(t *testing.T) {
	rt := &Runtime{}

	_, err := rt.Run(
		context.Background(),
		nil,
	)

	if err == nil {
		t.Fatal("expected error for nil workload")
	}
}

func TestRuntimeRunIntegration(t *testing.T) {
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Skip("AGENTGUARD_CGROUP_ROOT is not set")
	}

	id := fmt.Sprintf(
		"runtime-integration-%d",
		os.Getpid(),
	)

	w, err := workload.New(
		id,
		workload.Spec{
			Command: "/bin/cat",
			Args:    []string{"/proc/self/cgroup"},
			Resources: workload.ResourceSpec{
				MemoryBytes:  64 * 1024 * 1024,
				MaxProcesses: 16,
			},
		},
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	rt, err := New(Config{
		CgroupRoot:     root,
		CleanupTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("runtime New returned error: %v", err)
	}

	groupName := cgroupName(w.ID())
	groupPath := filepath.Join(root, groupName)

	result, err := rt.Run(
		context.Background(),
		w,
	)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if result.ExitCode != 0 {
		t.Fatalf(
			"unexpected exit code: got %d, want 0",
			result.ExitCode,
		)
	}

	if !strings.Contains(result.Stdout, groupName) {
		t.Fatalf(
			"child did not run in expected cgroup:\nstdout: %q\nexpected cgroup: %q",
			result.Stdout,
			groupName,
		)
	}

	if w.State() != workload.StateFinished {
		t.Fatalf(
			"unexpected workload state: got %s, want %s",
			w.State(),
			workload.StateFinished,
		)
	}

	if _, err := os.Stat(groupPath); !os.IsNotExist(err) {
		if err == nil {
			t.Fatalf(
				"workload cgroup still exists after cleanup: %q",
				groupPath,
			)
		}

		t.Fatalf(
			"stat workload cgroup after cleanup: %v",
			err,
		)
	}
}

func TestRuntimeTimeoutKillsEscapedDescendantIntegration(t *testing.T) {
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Skip("AGENTGUARD_CGROUP_ROOT is not set")
	}

	pidFile := filepath.Join(
		t.TempDir(),
		"escaped-child.pid",
	)

	script := `
/usr/bin/setsid /bin/sh -c '
	echo $$ > "$1"
	exec /bin/sleep 30
' sh "$1" &

while [ ! -s "$1" ]; do
	:
done

exec /bin/sleep 30
`

	w, err := workload.New(
		"escaped-descendant-test",
		workload.Spec{
			Command: "/bin/sh",
			Args: []string{
				"-c",
				script,
				"sh",
				pidFile,
			},
			Timeout: 1 * time.Second,
			Resources: workload.ResourceSpec{
				MemoryBytes:  64 * 1024 * 1024,
				MaxProcesses: 16,
			},
		},
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	rt, err := New(Config{
		CgroupRoot:     root,
		CleanupTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("runtime New returned error: %v", err)
	}

	start := time.Now()

	result, err := rt.Run(
		context.Background(),
		w,
	)

	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf(
			"runtime took too long to terminate escaped descendant: %v",
			elapsed,
		)
	}

	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if !result.TimedOut {
		t.Fatal("expected workload to time out")
	}

	if w.State() != workload.StateFailed {
		t.Fatalf(
			"unexpected workload state: got %s, want %s",
			w.State(),
			workload.StateFailed,
		)
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf(
			"failed to read escaped child PID: %v",
			err,
		)
	}

	pid, err := strconv.Atoi(
		strings.TrimSpace(string(data)),
	)
	if err != nil {
		t.Fatalf(
			"invalid escaped child PID %q: %v",
			string(data),
			err,
		)
	}

	assertProcessNotRunning(t, pid)

	groupPath := filepath.Join(
		root,
		cgroupName(w.ID()),
	)

	if _, err := os.Stat(groupPath); !os.IsNotExist(err) {
		if err == nil {
			t.Fatalf(
				"workload cgroup still exists after cleanup: %q",
				groupPath,
			)
		}

		t.Fatalf(
			"stat workload cgroup after cleanup: %v",
			err,
		)
	}
}

func assertProcessNotRunning(t *testing.T, pid int) {
	t.Helper()

	err := syscall.Kill(pid, 0)

	if errors.Is(err, syscall.ESRCH) {
		return
	}

	if err != nil {
		t.Fatalf(
			"check process %d: %v",
			pid,
			err,
		)
	}

	statusPath := fmt.Sprintf(
		"/proc/%d/status",
		pid,
	)

	data, err := os.ReadFile(statusPath)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}

		t.Fatalf(
			"read process %d status: %v",
			pid,
			err,
		)
	}

	for _, line := range strings.Split(
		string(data),
		"\n",
	) {
		if strings.HasPrefix(line, "State:") {
			if strings.Contains(line, "Z") {
				return
			}

			t.Fatalf(
				"escaped descendant %d is still running: %s",
				pid,
				line,
			)
		}
	}

	t.Fatalf(
		"could not determine state of process %d",
		pid,
	)
}

func eventTypes(events []audit.Event) []audit.EventType {
	types := make([]audit.EventType, 0, len(events))

	for _, event := range events {
		types = append(types, event.Type)
	}

	return types
}

func TestRuntimeRecordsNormalLifecycleEvents(t *testing.T) {
	w, err := workload.New(
		"audit-normal",
		workload.Spec{
			Command: "/bin/true",
		},
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	var events []audit.Event

	rt, _, _ := newTestRuntime(
		func(
			ctx context.Context,
			req runner.Request,
		) (runner.Result, error) {
			if err := req.Hooks.OnStarted(1234); err != nil {
				return runner.Result{}, err
			}

			return runner.Result{
				ExitCode: 0,
			}, nil
		},
	)

	rt.audit = audit.SinkFunc(func(event audit.Event) {
		events = append(events, event)
	})

	_, err = rt.Run(context.Background(), w)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got := eventTypes(events)

	want := []audit.EventType{
		audit.EventWorkloadPreparing,
		audit.EventWorkloadStarted,
		audit.EventCleanupStarted,
		audit.EventWorkloadFinished,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"unexpected event sequence:\ngot:  %v\nwant: %v",
			got,
			want,
		)
	}
}

func TestRuntimeRecordsTimeoutLifecycleEvents(t *testing.T) {
	w, err := workload.New(
		"audit-timeout",
		workload.Spec{
			Command: "/bin/sleep",
			Args:    []string{"10"},
		},
	)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	var events []audit.Event

	rt, _, _ := newTestRuntime(
		func(
			ctx context.Context,
			req runner.Request,
		) (runner.Result, error) {
			if err := req.Hooks.OnStarted(1234); err != nil {
				return runner.Result{}, err
			}

			if err := req.Hooks.OnTerminating(
				runner.TerminationTimeout,
			); err != nil {
				return runner.Result{
					TimedOut: true,
				}, err
			}

			return runner.Result{
				ExitCode: -1,
				TimedOut: true,
			}, nil
		},
	)

	rt.audit = audit.SinkFunc(func(event audit.Event) {
		events = append(events, event)
	})

	_, err = rt.Run(context.Background(), w)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got := eventTypes(events)

	want := []audit.EventType{
		audit.EventWorkloadPreparing,
		audit.EventWorkloadStarted,
		audit.EventWorkloadTerminating,
		audit.EventCleanupStarted,
		audit.EventWorkloadFailed,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"unexpected event sequence:\ngot:  %v\nwant: %v",
			got,
			want,
		)
	}
}
