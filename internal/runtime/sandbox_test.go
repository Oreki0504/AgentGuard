package runtime

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/audit"
	"github.com/Oreki0504/AgentGuard/internal/runner"
	"github.com/Oreki0504/AgentGuard/internal/runtime/sandbox/linux"
	"github.com/Oreki0504/AgentGuard/internal/workload"
)

func inspectLaunchConfig(t *testing.T, f *os.File) linux.Config {
	t.Helper()
	var size uint32
	if err := binary.Read(f, binary.BigEndian, &size); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(f, data); err != nil {
		t.Fatal(err)
	}
	var c linux.Config
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSandboxLifecycleRequiresReady(t *testing.T) {
	for _, mode := range []string{"success", "exec-error", "early-exit", "missing-exit"} {
		t.Run(mode, func(t *testing.T) {
			w, err := workload.New("sandbox-"+mode, workload.Spec{Command: "/bin/sh", Args: []string{"-c", "exit 42"}, Env: []string{"SECRET=not-for-audit"}})
			if err != nil {
				t.Fatal(err)
			}
			var allocated string
			var events []audit.Event
			rt, _, group := newTestRuntime(func(ctx context.Context, req runner.Request) (runner.Result, error) {
				c := inspectLaunchConfig(t, req.ExtraFiles[0])
				allocated = c.Rootfs
				if req.Command != "/trusted/launcher" || len(req.Env) != 0 || !reflect.DeepEqual(c.Env, []string{"SECRET=not-for-audit"}) {
					t.Fatal("request/config separation failed")
				}
				if w.State() != workload.StatePreparing {
					t.Fatal("started before READY")
				}
				if mode == "exec-error" {
					linux.WriteMessage(req.ExtraFiles[1], linux.Message{Version: linux.Version, Type: "ERROR", Stage: "exec", Reason: "failed"})
				}
				if mode == "success" || mode == "missing-exit" {
					linux.WriteMessage(req.ExtraFiles[1], linux.Message{Version: linux.Version, Type: "READY"})
					if mode == "success" {
						code := 42
						linux.WriteMessage(req.ExtraFiles[1], linux.Message{Version: linux.Version, Type: "EXIT", ExitCode: &code})
					}
				}
				if err := req.Hooks.OnStarted(123); err != nil {
					return runner.Result{}, err
				}
				if w.State() != workload.StatePreparing {
					t.Fatal("launcher start was treated as guest start")
				}
				if err := req.Startup.Wait(ctx); err != nil {
					return runner.Result{ExitCode: -1}, err
				}
				if err := req.Hooks.OnReady(123); err != nil {
					return runner.Result{}, err
				}
				return runner.Result{ExitCode: 0}, nil
			})
			files, err := linux.ShellFiles()
			if err != nil {
				t.Skip(err)
			}
			rt.sandbox = &SandboxConfig{Launcher: "/trusted/launcher", RootfsBase: t.TempDir(), StartupTimeout: time.Second, Files: files}
			rt.audit = audit.SinkFunc(func(e audit.Event) { events = append(events, e) })
			result, err := rt.Run(context.Background(), w)
			if mode == "success" {
				if err != nil || w.State() != workload.StateFinished || result.ExitCode != 42 {
					t.Fatalf("result=%+v state=%s err=%v", result, w.State(), err)
				}
			} else if err == nil || w.State() != workload.StateFailed {
				t.Fatalf("state=%s err=%v", w.State(), err)
			}
			if mode == "exec-error" || mode == "early-exit" {
				if !w.StartedAt().IsZero() {
					t.Fatal("setup failure emitted Started")
				}
			}
			if !group.killCalled || !group.waitEmptyCalled || !group.removeCalled {
				t.Fatal("incomplete cgroup cleanup")
			}
			if _, err := os.Stat(allocated); !os.IsNotExist(err) {
				t.Fatalf("rootfs remains: %v", err)
			}
			for _, e := range events {
				if strings.Contains(e.Reason, "not-for-audit") {
					t.Fatal("secret leaked into audit")
				}
			}
		})
	}
}

type cleanupFaultGroup struct {
	fakeCgroupGroup
	waitErr, killErr, removeErr error
	onWait                      func(context.Context)
}

func (g *cleanupFaultGroup) Kill() error { g.killCalled = true; return g.killErr }
func (g *cleanupFaultGroup) WaitEmpty(ctx context.Context) error {
	g.waitEmptyCalled = true
	if g.onWait != nil {
		g.onWait(ctx)
	}
	return g.waitErr
}
func (g *cleanupFaultGroup) Remove() error { g.removeCalled = true; return g.removeErr }

func TestRootfsCleanupRequiresConfirmedEmptyGroup(t *testing.T) {
	allocation, err := allocateRootfs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	g := &cleanupFaultGroup{waitErr: errors.New("still populated")}
	rt := &Runtime{cleanupTimeout: time.Second}
	if err := rt.cleanupGroup(g, true, allocation); err == nil {
		t.Fatal("cleanup error lost")
	}
	if _, err := os.Stat(allocation.path); err != nil {
		t.Fatal("rootfs removed before empty confirmation")
	}
	if g.removeCalled {
		t.Fatal("unconfirmed cgroup removed")
	}
	g.waitErr = nil
	g.onWait = func(ctx context.Context) {
		if ctx.Err() != nil {
			t.Fatal("cleanup context canceled")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("cleanup has no deadline")
		}
	}
	if err := rt.cleanupGroup(g, true, allocation); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(allocation.path); !os.IsNotExist(err) {
		t.Fatal("rootfs was not removed")
	}
}

func TestRootfsNeverRecursivelyDeletesUnexpectedContent(t *testing.T) {
	a, err := allocateRootfs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(a.path, "unexpected")
	os.WriteFile(file, []byte("keep"), 0600)
	if err := a.remove(context.Background()); err == nil {
		t.Fatal("nonempty rootfs accepted")
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep" {
		t.Fatal("unexpected content removed")
	}
}

func TestRootfsRejectsReplacedAllocation(t *testing.T) {
	a, err := allocateRootfs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	os.Rename(a.path, a.path+"-original")
	os.Mkdir(a.path, 0700)
	if err := a.remove(context.Background()); err == nil {
		t.Fatal("replacement rootfs deleted")
	}
}

func TestRootfsRejectsHostMountReferences(t *testing.T) {
	for _, line := range []string{
		`42 1 0:1 / /tmp/root\040fs rw - tmpfs tmpfs rw`,
		`42 1 0:1 / /tmp/root\040fs/child rw - tmpfs tmpfs rw`,
		`42 1 0:1 /tmp/root\040fs /somewhere-else rw - tmpfs tmpfs rw`,
		`malformed`,
	} {
		if err := checkMountReferences(strings.NewReader(line), "/tmp/root fs"); err == nil {
			t.Fatalf("unsafe mountinfo accepted: %s", line)
		}
	}
	if err := checkMountReferences(strings.NewReader(`42 1 0:1 / /tmp/root\040fs-other rw - tmpfs tmpfs rw`), "/tmp/root fs"); err != nil {
		t.Fatal(err)
	}
}

func TestRejectUntrustedLauncher(t *testing.T) {
	p := filepath.Join(t.TempDir(), "launcher")
	os.WriteFile(p, []byte("#!/bin/sh\n"), 0755)
	if _, err := New(Config{CgroupRoot: "/unused", Sandbox: &SandboxConfig{Launcher: p}}); err == nil {
		t.Fatal("untrusted launcher accepted")
	}
}

type faultBackend struct{ group cgroupGroup }

func (b faultBackend) Create(string, workload.ResourceSpec) (cgroupGroup, error) { return b.group, nil }

func TestCleanupFailureIsAuditedAndFailsWorkload(t *testing.T) {
	for _, stage := range []string{"kill", "wait", "remove"} {
		t.Run(stage, func(t *testing.T) {
			g := &cleanupFaultGroup{}
			switch stage {
			case "kill":
				g.killErr = errors.New("kill failure")
			case "wait":
				g.waitErr = errors.New("wait failure")
			case "remove":
				g.removeErr = errors.New("remove failure")
			}
			var events []audit.Event
			rt := &Runtime{cgroups: faultBackend{g}, cleanupTimeout: time.Second, audit: audit.SinkFunc(func(e audit.Event) { events = append(events, e) }),
				execute: func(_ context.Context, req runner.Request) (runner.Result, error) {
					if err := req.Hooks.OnStarted(1); err != nil {
						return runner.Result{}, err
					}
					return runner.Result{ExitCode: 0}, nil
				}}
			w, _ := workload.New("cleanup-failure", workload.Spec{Command: "/bin/true"})
			_, err := rt.Run(context.Background(), w)
			if err == nil || w.State() != workload.StateFailed {
				t.Fatalf("state=%s err=%v", w.State(), err)
			}
			found := false
			for _, e := range events {
				if e.Type == audit.EventCleanupFailed && e.WorkloadID == w.ID() {
					found = true
				}
			}
			if !found {
				t.Fatal("cleanup failure not audited")
			}
		})
	}
}
