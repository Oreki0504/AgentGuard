package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/audit"
	"github.com/Oreki0504/AgentGuard/internal/runner"
	"github.com/Oreki0504/AgentGuard/internal/runtime/sandbox/linux"
	"github.com/Oreki0504/AgentGuard/internal/workload"
)

func sandboxIntegrationConfig(t *testing.T) Config {
	t.Helper()
	root, launcher := os.Getenv("AGENTGUARD_CGROUP_ROOT"), os.Getenv("AGENTGUARD_LAUNCHER")
	if root == "" && launcher == "" {
		t.Skip("sandbox integration requires AGENTGUARD_CGROUP_ROOT and AGENTGUARD_LAUNCHER")
	}
	if root == "" || launcher == "" {
		t.Fatal("explicit sandbox prerequisites are incomplete")
	}
	files, err := linux.ShellFiles()
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, linux.File{Source: exe, Target: "/bin/attack"})
	return Config{CgroupRoot: root, Sandbox: &SandboxConfig{Launcher: launcher, Files: files}, CleanupTimeout: 3 * time.Second}
}

func runSandboxIntegration(t *testing.T, cfg Config, spec workload.Spec) (runner.Result, *workload.Workload, []audit.Event, error) {
	t.Helper()
	var events []audit.Event
	cfg.Audit = audit.SinkFunc(func(e audit.Event) { events = append(events, e) })
	rt, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w, err := workload.New(fmt.Sprintf("sandbox-%d-%d", os.Getpid(), time.Now().UnixNano()), spec)
	if err != nil {
		t.Fatal(err)
	}
	var rootfs string
	rt.execute = func(ctx context.Context, req runner.Request) (runner.Result, error) {
		rootfs = inspectLaunchConfig(t, req.ExtraFiles[0]).Rootfs
		return runner.Run(ctx, req)
	}
	result, runErr := rt.Run(context.Background(), w)
	if rootfs != "" {
		if _, err := os.Stat(rootfs); !os.IsNotExist(err) {
			t.Fatalf("rootfs leaked at %s: %v", rootfs, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.CgroupRoot, cgroupName(w.ID()))); !os.IsNotExist(err) {
		t.Fatalf("cgroup leaked: %v", err)
	}
	return result, w, events, runErr
}

func sandboxSpec(command string, args ...string) workload.Spec {
	return workload.Spec{Command: command, Args: args, Timeout: 5 * time.Second,
		Resources: workload.ResourceSpec{MemoryBytes: 128 * 1024 * 1024, MaxProcesses: 128, CPUMilliCores: 1000}}
}

func TestSandboxExecutionIntegration(t *testing.T) {
	cfg := sandboxIntegrationConfig(t)
	t.Setenv("HOST_SECRET", "must-not-leak")
	workspace, scratch := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(workspace, "host.txt"), []byte("approved"), 0600)
	cfg.Sandbox.Mounts = []linux.BindMount{{Source: workspace, Target: "/workspace", ReadOnly: true}, {Source: scratch, Target: "/scratch"}}
	spec := sandboxSpec("/bin/sh", "-c", `printf '%s:%s:%s:' "$1" "$EXPLICIT" "${HOST_SECRET-unset}"; pwd; exit 42`, "sh", "actual-arg")
	spec.Env = []string{"EXPLICIT=value"}
	spec.WorkingDir = "/workspace"
	result, w, events, err := runSandboxIntegration(t, cfg, spec)
	if err != nil || w.State() != workload.StateFinished || result.ExitCode != 42 || result.Stdout != "actual-arg:value:unset:/workspace\n" {
		t.Fatalf("result=%+v state=%s err=%v", result, w.State(), err)
	}
	want := []audit.EventType{audit.EventWorkloadPreparing, audit.EventWorkloadStarted, audit.EventCleanupStarted, audit.EventWorkloadFinished}
	if fmt.Sprint(eventTypes(events)) != fmt.Sprint(want) {
		t.Fatalf("unexpected lifecycle: %v", eventTypes(events))
	}
}

func TestSandboxFilesystemAndProcessAttacksIntegration(t *testing.T) {
	cfg := sandboxIntegrationConfig(t)
	workspace, scratch := t.TempDir(), t.TempDir()
	hostSecret := filepath.Join(t.TempDir(), "host-secret")
	os.WriteFile(hostSecret, []byte("unexposed"), 0600)
	os.WriteFile(filepath.Join(workspace, "host.txt"), []byte("approved"), 0600)
	cfg.Sandbox.Mounts = []linux.BindMount{{Source: workspace, Target: "/workspace", ReadOnly: true}, {Source: scratch, Target: "/scratch"}}
	// Deliberately leave a host FD without CLOEXEC. The launcher must ensure
	// even a badly behaved embedding application cannot leak it into the guest.
	fd, err := syscall.Open(hostSecret, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	spec := sandboxSpec("/bin/attack", "-test.run=^TestSandboxGuest$", "--", "attacks")
	spec.Env = []string{"AGENTGUARD_TEST_GUEST=1", "HOST_SECRET_PATH=" + hostSecret, "HOST_PID=" + strconv.Itoa(os.Getpid()), "HOST_FD=" + strconv.Itoa(fd)}
	result, _, _, err := runSandboxIntegration(t, cfg, spec)
	if err != nil || result.ExitCode != 0 || !strings.Contains(result.Stdout, "attacks-denied") {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := os.Stat(filepath.Join(workspace, "write-bypass")); !os.IsNotExist(err) {
		t.Fatal("read-only host changed")
	}
	if data, err := os.ReadFile(filepath.Join(scratch, "written")); err != nil || string(data) != "allowed" {
		t.Fatalf("scratch write missing: %q %v", data, err)
	}
	// The same directory model must explicitly permit a writable workspace.
	cfg.Sandbox.Mounts[0].ReadOnly = false
	result, _, _, err = runSandboxIntegration(t, cfg, sandboxSpec("/bin/sh", "-c", "printf allowed > /workspace/writable"))
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("writable workspace result=%+v err=%v", result, err)
	}
	if data, err := os.ReadFile(filepath.Join(workspace, "writable")); err != nil || string(data) != "allowed" {
		t.Fatal("writable workspace failed")
	}
}

func TestSandboxSetupFailureIntegration(t *testing.T) {
	for _, mode := range []string{"exec", "working-directory", "rootfs"} {
		t.Run(mode, func(t *testing.T) {
			cfg := sandboxIntegrationConfig(t)
			spec := sandboxSpec("/bin/missing")
			if mode == "working-directory" {
				spec.Command = "/bin/sh"
				spec.WorkingDir = "/missing"
			}
			if mode == "rootfs" {
				f, err := os.CreateTemp(t.TempDir(), "oversized-tool-")
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Truncate(33 * 1024 * 1024); err != nil {
					t.Fatal(err)
				}
				f.Close()
				cfg.Sandbox.Files = append(cfg.Sandbox.Files, linux.File{Source: f.Name(), Target: "/bin/oversized"})
			}
			start := time.Now()
			result, w, events, err := runSandboxIntegration(t, cfg, spec)
			if err == nil || w.State() != workload.StateFailed || !w.StartedAt().IsZero() {
				t.Fatalf("result=%+v state=%s err=%v", result, w.State(), err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("explicit setup error waited for timeout")
			}
			failed := false
			for _, e := range events {
				if e.Type == audit.EventWorkloadStarted {
					t.Fatal("false WorkloadStarted")
				}
				if e.Type == audit.EventSandboxFailed {
					failed = true
				}
			}
			if !failed {
				t.Fatal("setup failure not audited")
			}
		})
	}
}

func TestSandboxReaperIntegration(t *testing.T) {
	for _, mode := range []string{"orphan", "reap"} {
		t.Run(mode, func(t *testing.T) {
			cfg := sandboxIntegrationConfig(t)
			spec := sandboxSpec("/bin/attack", "-test.run=^TestSandboxGuest$", "--", mode)
			spec.Env = []string{"AGENTGUARD_TEST_GUEST=1"}
			start := time.Now()
			result, w, _, err := runSandboxIntegration(t, cfg, spec)
			if err != nil || w.State() != workload.StateFinished || result.ExitCode != 0 {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if mode == "orphan" && (!strings.Contains(result.Stdout, "orphan-reaped") || time.Since(start) < 100*time.Millisecond) {
				t.Fatal("init exited before its orphan")
			}
		})
	}
}

func TestSandboxTerminationIntegration(t *testing.T) {
	for _, mode := range []string{"timeout", "startup-timeout", "cancel", "launcher-crash", "init-crash", "signal-forward"} {
		t.Run(mode, func(t *testing.T) {
			cfg := sandboxIntegrationConfig(t)
			rt, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			spec := sandboxSpec("/bin/attack", "-test.run=^TestSandboxGuest$", "--", "linger")
			if mode == "signal-forward" {
				spec.Args[len(spec.Args)-1] = "linger-child"
			}
			spec.Env = []string{"AGENTGUARD_TEST_GUEST=1"}
			spec.Timeout = 400 * time.Millisecond
			w, err := workload.New(fmt.Sprintf("termination-%d-%s", os.Getpid(), mode), spec)
			if err != nil {
				t.Fatal(err)
			}
			var rootfs string
			rt.execute = func(ctx context.Context, req runner.Request) (runner.Result, error) {
				rootfs = inspectLaunchConfig(t, req.ExtraFiles[0]).Rootfs
				if mode == "startup-timeout" {
					req.Startup.Timeout = 100 * time.Millisecond
					req.Startup.Wait = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
				}
				ready := req.Hooks.OnReady
				req.Hooks.OnReady = func(pid int) error {
					if err := ready(pid); err != nil {
						return err
					}
					switch mode {
					case "signal-forward":
						return syscall.Kill(pid, syscall.SIGTERM)
					case "cancel":
						cancel()
					case "launcher-crash":
						return syscall.Kill(pid, syscall.SIGKILL)
					case "init-crash":
						data, err := os.ReadFile(filepath.Join(cfg.CgroupRoot, cgroupName(w.ID()), "cgroup.procs"))
						if err != nil {
							return err
						}
						for _, value := range strings.Fields(string(data)) {
							status, err := os.ReadFile("/proc/" + value + "/status")
							if err != nil {
								continue
							}
							for _, line := range strings.Split(string(status), "\n") {
								if strings.HasPrefix(line, "NSpid:") {
									fields := strings.Fields(line)
									if len(fields) >= 3 && fields[len(fields)-1] == "1" {
										p, _ := strconv.Atoi(value)
										return syscall.Kill(p, syscall.SIGKILL)
									}
								}
							}
						}
						return errors.New("namespace init PID not found")
					}
					return nil
				}
				return runner.Run(ctx, req)
			}
			result, runErr := rt.Run(ctx, w)
			wantState := workload.StateFailed
			if mode == "signal-forward" {
				wantState = workload.StateFinished
				if runErr != nil || result.ExitCode != 143 {
					t.Fatalf("signal result=%+v err=%v", result, runErr)
				}
			}
			if w.State() != wantState {
				t.Fatalf("state=%s result=%+v err=%v", w.State(), result, runErr)
			}
			if mode != "startup-timeout" && w.StartedAt().IsZero() {
				t.Fatalf("test did not reach workload: %+v %v", result, runErr)
			}
			if mode == "startup-timeout" && (!w.StartedAt().IsZero() || !result.TimedOut) {
				t.Fatal("startup timeout lifecycle incorrect")
			}
			if mode == "timeout" && !result.TimedOut {
				t.Fatal("timeout lost")
			}
			if mode == "timeout" && !strings.Contains(result.Stdout, "detached-child") {
				t.Fatalf("timeout did not exercise detached descendant: %+v %v", result, runErr)
			}
			if mode == "cancel" && !result.Canceled {
				t.Fatal("cancel lost")
			}
			if _, err := os.Stat(rootfs); !os.IsNotExist(err) {
				t.Fatalf("rootfs leaked: %v", err)
			}
			if _, err := os.Stat(filepath.Join(cfg.CgroupRoot, cgroupName(w.ID()))); !os.IsNotExist(err) {
				t.Fatalf("cgroup leaked: %v", err)
			}
		})
	}
}

// Test-only executable payload. The production launcher has no fault-injection
// environment variables or alternate probe modes.
func TestSandboxGuest(t *testing.T) {
	if os.Getenv("AGENTGUARD_TEST_GUEST") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	fail := func(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(90) }
	child := func(mode string) *exec.Cmd {
		cmd := exec.Command("/bin/attack", "-test.run=^TestSandboxGuest$", "--", mode)
		cmd.Env = []string{"AGENTGUARD_TEST_GUEST=1"}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		return cmd
	}
	switch mode {
	case "attacks":
		if os.Getpid() == 1 || os.Getppid() != 1 {
			fail("untrusted workload is init")
		}
		for _, p := range []string{"/etc/passwd", os.Getenv("HOST_SECRET_PATH"), "/proc/" + os.Getenv("HOST_PID"), "/.oldroot", "/proc/1/root/etc/passwd", "/proc/1/fd/4"} {
			if f, err := os.Open(p); err == nil {
				f.Close()
				fail("unexposed resource accessible: %s", p)
			}
		}
		data, err := os.ReadFile("/workspace/host.txt")
		if err != nil || string(data) != "approved" {
			fail("approved file unavailable: %v", err)
		}
		if err := os.WriteFile("/workspace/write-bypass", []byte("bad"), 0600); !errors.Is(err, syscall.EROFS) {
			fail("expected kernel EROFS, got %v", err)
		}
		if err := syscall.Mount("", "/workspace", "", syscall.MS_BIND|syscall.MS_REMOUNT, ""); err == nil {
			fail("read-only remount succeeded")
		}
		if err := syscall.Unmount("/workspace", 0); err == nil {
			fail("unmount succeeded")
		}
		if err := syscall.Mount("tmpfs", "/workspace", "tmpfs", 0, ""); err == nil {
			fail("mount succeeded")
		}
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			fail("read status: %v", err)
		}
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "CapEff:") || strings.HasPrefix(line, "CapPrm:") || strings.HasPrefix(line, "CapBnd:") {
				fields := strings.Fields(line)
				if fields[1] != "0000000000000000" {
					fail("capability retained: %s", line)
				}
			}
		}
		fds, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			fail("read fd list: %v", err)
		}
		for _, fd := range fds {
			n, _ := strconv.Atoi(fd.Name())
			if n <= 2 {
				continue
			}
			link, _ := os.Readlink("/proc/self/fd/" + fd.Name())
			if strings.HasPrefix(link, "pipe:") || strings.Contains(link, "agentguard") || strings.HasPrefix(link, "/home/") {
				fail("host/control FD leaked: %s", link)
			}
		}
		if err := os.WriteFile("/scratch/written", []byte("allowed"), 0600); err != nil {
			fail("scratch denied: %v", err)
		}
		data, err = os.ReadFile("/proc/self/cgroup")
		if err != nil || !strings.Contains(string(data), "agentguard-") {
			fail("cgroup attribution missing")
		}
		// Even a nested user/mount namespace must not unlock the inherited ro
		// bind. AppArmor may deny its creation; both routes must deny the write.
		nested := child("nested-remount")
		nested.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}}, GidMappingsEnableSetgroups: false}
		if err := nested.Run(); err != nil {
			if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
				fail("nested namespace test failed unexpectedly: %v", err)
			}
		}
		fmt.Println("attacks-denied")
	case "nested-remount":
		if err := syscall.Mount("", "/workspace", "", syscall.MS_BIND|syscall.MS_REMOUNT, ""); err == nil {
			fail("nested namespace unlocked read-only mount")
		}
	case "orphan":
		if err := child("orphan-child").Start(); err != nil {
			fail("orphan fork: %v", err)
		}
	case "orphan-child":
		time.Sleep(150 * time.Millisecond)
		if os.Getppid() != 1 {
			fail("orphan not reparented")
		}
		fmt.Println("orphan-reaped")
	case "reap":
		if err := child("orphan").Run(); err != nil {
			fail("orphan parent: %v", err)
		}
		time.Sleep(350 * time.Millisecond)
		entries, _ := os.ReadDir("/proc")
		for _, entry := range entries {
			if _, err := strconv.Atoi(entry.Name()); err != nil {
				continue
			}
			data, _ := os.ReadFile("/proc/" + entry.Name() + "/status")
			if strings.Contains(string(data), "State:\tZ") {
				fail("unreaped zombie: %s", entry.Name())
			}
		}
	case "linger":
		if err := child("linger-child").Start(); err != nil {
			fail("escaped descendant fork: %v", err)
		}
		time.Sleep(30 * time.Second)
	case "linger-child":
		fmt.Println("detached-child")
		time.Sleep(30 * time.Second)
	default:
		fail("unknown guest mode")
	}
	os.Exit(0)
}
