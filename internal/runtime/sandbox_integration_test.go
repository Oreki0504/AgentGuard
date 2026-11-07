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
	if ns := os.Getenv("AGENTGUARD_PHASE2C_NAMESPACE"); ns != "" {
		if !strings.HasPrefix(ns, "agentguard-phase2c-") || strings.ContainsAny(ns, "/:\x00") {
			t.Fatal("invalid isolated policy namespace")
		}
		for name, expected := range map[string]string{".ns_name": ns, ".stacked": "no", ".ns_stacked": "no"} {
			data, err := os.ReadFile("/sys/kernel/security/apparmor/" + name)
			if err != nil || strings.TrimSpace(string(data)) != expected {
				t.Fatalf("unexpected driver namespace/stacking %s=%q: %v", name, data, err)
			}
		}
		if os.Getuid() == 0 || os.Geteuid() != os.Getuid() || os.Getegid() != os.Getgid() {
			t.Fatal("production-chain test requires ordinary matching host credentials")
		}
		t.Logf("driver namespace=%s stacked=no ns_stacked=no host_uid=%d host_gid=%d", ns, os.Getuid(), os.Getgid())
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

func runSandboxIntegration(t *testing.T, cfg Config, spec workload.Spec, mutate ...func(*runner.Request)) (runner.Result, *workload.Workload, []audit.Event, error) {
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
	readyCount := 0
	rt.execute = func(ctx context.Context, req runner.Request) (runner.Result, error) {
		rootfs = inspectLaunchConfig(t, req.ExtraFiles[0]).Rootfs
		t.Logf("production case cgroup=%s rootfs=%s", filepath.Join(cfg.CgroupRoot, cgroupName(w.ID())), rootfs)
		started, ready := req.Hooks.OnStarted, req.Hooks.OnReady
		req.Hooks.OnStarted = func(pid int) error {
			t.Logf("production launcher host_pid=%d", pid)
			return started(pid)
		}
		req.Hooks.OnReady = func(pid int) error {
			readyCount++
			return ready(pid)
		}
		for _, change := range mutate {
			change(&req)
		}
		return runner.Run(ctx, req)
	}
	result, runErr := rt.Run(context.Background(), w)
	t.Logf("READY=%d guest_exit=%d state=%s error=%v stdout=%q stderr=%q", readyCount, result.ExitCode, w.State(), runErr, result.Stdout, result.Stderr)
	if readyCount > 1 || (runErr == nil && readyCount != 1) {
		t.Fatalf("invalid readiness count: %d", readyCount)
	}
	if rootfs != "" {
		if _, err := os.Stat(rootfs); !os.IsNotExist(err) {
			t.Fatalf("rootfs leaked at %s: %v", rootfs, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.CgroupRoot, cgroupName(w.ID()))); !os.IsNotExist(err) {
		t.Fatalf("cgroup leaked: %v", err)
	}
	t.Log("Runtime cleanup completed; rootfs and cgroup absent")
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
	spec := sandboxSpec("/bin/sh", "-c", `test "$(/bin/sh -c 'printf child')" = child || exit 99; printf '%s:%s:%s:' "$1" "$EXPLICIT" "${HOST_SECRET-unset}"; pwd; exit 42`, "sh", "actual-arg")
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

// One production launch checks the Go image and both Go/shell descendants.
func TestSandboxConfinementIntegration(t *testing.T) {
	cfg := sandboxIntegrationConfig(t)
	spec := sandboxSpec("/bin/attack", "-test.run=^TestSandboxGuest$", "--", "confinement")
	spec.Env = []string{"AGENTGUARD_TEST_GUEST=1"}
	result, w, events, err := runSandboxIntegration(t, cfg, spec)
	if err != nil || w.State() != workload.StateFinished || result.ExitCode != 0 ||
		result.Stdout != "go-child-confined\ngo-guest-confined\n" || result.Stderr != "" {
		t.Fatalf("result=%+v state=%s err=%v", result, w.State(), err)
	}
	want := []audit.EventType{audit.EventWorkloadPreparing, audit.EventWorkloadStarted, audit.EventCleanupStarted, audit.EventWorkloadFinished}
	if fmt.Sprint(eventTypes(events)) != fmt.Sprint(want) {
		t.Fatalf("unexpected lifecycle: %v", eventTypes(events))
	}
}

func TestSandboxImmediateExitIntegration(t *testing.T) {
	cfg := sandboxIntegrationConfig(t)
	result, w, _, err := runSandboxIntegration(t, cfg, sandboxSpec("/bin/sh", "-c", "exit 73"))
	if err != nil || result.ExitCode != 73 || result.Stdout != "" || result.Stderr != "" ||
		w.State() != workload.StateFinished || w.StartedAt().IsZero() {
		t.Fatalf("immediate exit result=%+v state=%v err=%v", result, w.State(), err)
	}
}

func TestSandboxBootstrapSourceFDIntegration(t *testing.T) {
	cfg := sandboxIntegrationConfig(t)
	wrong, err := os.Open("/usr/bin/dash")
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	result, w, events, err := runSandboxIntegration(t, cfg, sandboxSpec("/bin/sh", "-c", "exit 0"), func(req *runner.Request) {
		// Only the test driver substitutes this source FD. Launcher must bind
		// the supplied handle to the fixed installed Bootstrap before UserNS.
		req.ExtraFiles[len(req.ExtraFiles)-1] = wrong
	})
	requireSandboxStartupFailure(t, w, events, err, "config", "bootstrap source identity mismatch")
	if result.Stdout != "" || result.Stderr != "" {
		t.Fatalf("unexpected output: %+v", result)
	}
}

func TestSandboxWorkloadLabelIntegration(t *testing.T) {
	if os.Getenv("AGENTGUARD_PHASE2C_BAD_LABEL") != "1" {
		t.Skip("requires the separately authorized wrong-label isolated policy")
	}
	if os.Getenv("AGENTGUARD_PHASE2C_NAMESPACE") == "" {
		t.Fatal("negative policy requires isolated namespace")
	}
	cfg := sandboxIntegrationConfig(t)
	result, w, events, err := runSandboxIntegration(t, cfg, sandboxSpec("/bin/sh", "-c", "exit 0"))
	requireSandboxStartupFailure(t, w, events, err, "exec", "cannot confirm and resume Guest exec")
	if !strings.Contains(result.Stderr, "agentguard-bootstrap: AppArmor label\n") || result.Stdout != "" {
		t.Fatalf("wrong label did not fail at C label check: %+v", result)
	}
}

func requireSandboxStartupFailure(t *testing.T, w *workload.Workload, events []audit.Event, err error, stage, reason string) {
	t.Helper()
	var failure *linux.Failure
	if !errors.As(err, &failure) || failure.Stage != stage || failure.Reason != reason ||
		w.State() != workload.StateFailed || !w.StartedAt().IsZero() {
		t.Fatalf("unexpected startup failure: state=%v failure=%+v err=%v", w.State(), failure, err)
	}
	failed := false
	for _, event := range events {
		if event.Type == audit.EventWorkloadStarted {
			t.Fatal("false Running on failed startup")
		}
		if event.Type == audit.EventSandboxFailed {
			failed = true
		}
	}
	if !failed {
		t.Fatal("missing sandbox failure audit")
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
			spec := sandboxSpec("/bin/sh", "-c", "exit 0")
			if mode == "exec" {
				// The executable is approved; omit its loader so failure occurs
				// at C execve, rather than at host configuration validation.
				var files []linux.File
				for _, file := range cfg.Sandbox.Files {
					if file.Target != "/lib64/ld-linux-x86-64.so.2" {
						files = append(files, file)
					}
				}
				cfg.Sandbox.Files = files
			}
			if mode == "working-directory" {
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
			var failure *linux.Failure
			if !errors.As(err, &failure) {
				t.Fatalf("missing typed failure: %v", err)
			}
			if mode == "exec" && (failure.Stage != "exec" || !strings.Contains(result.Stderr, "agentguard-bootstrap: guest exec\n")) {
				t.Fatalf("wrong Exec failure stage: %+v stderr=%q", failure, result.Stderr)
			}
			if mode == "rootfs" && failure.Stage != "rootfs" {
				t.Fatalf("wrong rootfs stage: %+v", failure)
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
	for _, mode := range []string{"timeout", "startup-timeout", "startup-cancel", "cancel", "launcher-crash", "init-crash", "signal-forward"} {
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
			readyCount := 0
			rt.execute = func(ctx context.Context, req runner.Request) (runner.Result, error) {
				rootfs = inspectLaunchConfig(t, req.ExtraFiles[0]).Rootfs
				t.Logf("production case cgroup=%s rootfs=%s", filepath.Join(cfg.CgroupRoot, cgroupName(w.ID())), rootfs)
				started := req.Hooks.OnStarted
				req.Hooks.OnStarted = func(pid int) error {
					t.Logf("production launcher host_pid=%d", pid)
					if err := started(pid); err != nil {
						return err
					}
					if mode == "startup-cancel" {
						cancel()
					}
					return nil
				}
				if mode == "startup-timeout" {
					req.Startup.Timeout = 100 * time.Millisecond
					req.Startup.Wait = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
				}
				ready := req.Hooks.OnReady
				req.Hooks.OnReady = func(pid int) error {
					readyCount++
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
			t.Logf("READY=%d guest_exit=%d state=%s timed_out=%t canceled=%t error=%v stdout=%q stderr=%q", readyCount, result.ExitCode, w.State(), result.TimedOut, result.Canceled, runErr, result.Stdout, result.Stderr)
			starting := mode == "startup-timeout" || mode == "startup-cancel"
			if (starting && readyCount != 0) || (!starting && readyCount != 1) {
				t.Fatalf("invalid readiness count %d", readyCount)
			}
			if mode == "startup-cancel" && (!result.Canceled || !w.StartedAt().IsZero()) {
				t.Fatal("startup cancellation lifecycle incorrect")
			}
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
			if !starting && w.StartedAt().IsZero() {
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
			t.Log("Runtime cleanup completed; rootfs and cgroup absent")
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
		// Separate process group exercises cgroup cleanup without requesting
		// setsid, which the unchanged production filter deliberately denies.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		return cmd
	}
	switch mode {
	case "confinement", "confinement-child":
		if err := checkGuestConfinement(); err != nil {
			fail("confinement: %v", err)
		}
		if mode == "confinement-child" {
			fmt.Println("go-child-confined")
			break
		}
		goChild := exec.Command("/bin/attack", "-test.run=^TestSandboxGuest$", "--", "confinement-child")
		goChild.Env = []string{"AGENTGUARD_TEST_GUEST=1"}
		goChild.Stdout, goChild.Stderr = os.Stdout, os.Stderr
		if err := goChild.Run(); err != nil {
			fail("Go child: %v", err)
		}
		output, err := exec.Command("/bin/sh", "-c", "printf shell-child").CombinedOutput()
		if err != nil || string(output) != "shell-child" {
			fail("shell child: %q %v", output, err)
		}
		fmt.Println("go-guest-confined")
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

// Executed only inside the explicitly selected Go Guest and its Go child.
func checkGuestConfinement() error {
	label, err := os.ReadFile("/proc/self/attr/apparmor/current")
	if err != nil || string(label) != "agentguard-launcher//workload (enforce)\n" {
		return fmt.Errorf("label=%q: %v", label, err)
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if !strings.Contains(string(status), field+":\t0000000000000000\n") {
			return fmt.Errorf("nonzero or absent %s", field)
		}
	}
	for query, expected := range map[uintptr]uintptr{39 /* PR_GET_NO_NEW_PRIVS */ : 1, 21 /* PR_GET_SECCOMP */ : 2} {
		value, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, query, 0, 0, 0, 0, 0)
		if errno != 0 || value != expected {
			return fmt.Errorf("prctl %d=%d: %v", query, value, errno)
		}
	}
	if !strings.Contains(string(status), "NoNewPrivs:\t1\n") || !strings.Contains(string(status), "Seccomp:\t2\n") {
		return fmt.Errorf("missing status NNP/seccomp")
	}
	// statfs is deliberately absent from the Guest syscall allowlist. Read
	// the kernel's mountinfo instead; PID1 already checks Statfs before Cx.
	mounts, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("read mountinfo: %w", err)
	}
	if err := checkGuestMountinfo(mounts); err != nil {
		return err
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			return err
		}
		if fd <= 2 {
			continue
		}
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno == syscall.EBADF {
			continue
		} // closed enumeration descriptor
		if errno != 0 {
			return fmt.Errorf("F_GETFD %d: %v", fd, errno)
		}
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil {
			return err
		}
		if target != "anon_inode:[eventpoll]" && target != "anon_inode:[eventfd]" {
			return fmt.Errorf("unexpected inherited FD %d: %s", fd, target)
		}
	}
	if file, err := os.OpenFile("/bin/attack", os.O_WRONLY, 0); err == nil {
		file.Close()
		return fmt.Errorf("executable layer writable")
	}
	if file, err := os.Open("/proc/1/fd/4"); err == nil {
		file.Close()
		return fmt.Errorf("PID1 status channel accessible")
	}
	for _, target := range []string{"/tmp", "/workspace"} {
		file, err := os.CreateTemp(target, "confinement-")
		if err != nil {
			return err
		}
		if _, err := file.WriteString("allowed"); err != nil {
			file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		if err := os.Remove(file.Name()); err != nil {
			return err
		}
	}
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); err != syscall.EPERM {
		if err == nil {
			syscall.Close(fd)
		}
		return fmt.Errorf("socket denial: %v", err)
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0, 0); errno != syscall.EPERM {
		return fmt.Errorf("seccomp prctl argument restriction: %v", errno)
	}
	return nil
}

func checkGuestMountinfo(data []byte) error {
	found := make(map[string]string)
	ids := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return fmt.Errorf("malformed mountinfo line")
		}
		target := fields[4]
		if target != "/" && target != "/tmp" && target != "/workspace" {
			continue
		}
		if _, seen := found[target]; seen || ids[fields[0]] {
			return fmt.Errorf("duplicate or shared mount at %s", target)
		}
		separator := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) || fields[separator+1] != "tmpfs" {
			return fmt.Errorf("expected private tmpfs at %s", target)
		}
		options := make(map[string]bool)
		for _, option := range strings.Split(fields[5], ",") {
			options[option] = true
		}
		readOnly := target == "/"
		if options["ro"] != readOnly || options["rw"] == readOnly ||
			!options["nosuid"] || !options["nodev"] || options["noexec"] == readOnly {
			return fmt.Errorf("unexpected mount options %s: %s", target, fields[5])
		}
		found[target] = fields[0]
		ids[fields[0]] = true
	}
	if len(found) != 3 {
		return fmt.Errorf("missing private root/tmp/workspace mount")
	}
	return nil
}

func TestGuestMountinfoRejectsUnsafeLayout(t *testing.T) {
	valid := "10 1 0:10 / / ro,nosuid,nodev - tmpfs tmpfs ro\n" +
		"11 10 0:11 / /tmp rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n" +
		"12 10 0:12 / /workspace rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n"
	if err := checkGuestMountinfo([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]string{
		"writable executable root": strings.Replace(valid, "/ ro,nosuid", "/ rw,nosuid", 1),
		"executable tmp":           strings.Replace(valid, "/tmp rw,nosuid,nodev,noexec", "/tmp rw,nosuid,nodev", 1),
		"readonly workspace":       strings.Replace(valid, "/workspace rw", "/workspace ro", 1),
		"missing nodev":            strings.Replace(valid, "nodev", "", 1),
		"missing nosuid":           strings.Replace(valid, "nosuid", "", 1),
		"shared mount":             strings.Replace(valid, "12 10", "11 10", 1),
		"duplicate mountpoint":     strings.Replace(valid, "/workspace", "/tmp", 1),
		"wrong filesystem":         strings.Replace(valid, "- tmpfs", "- ext4", 1),
		"missing workspace":        strings.Join(strings.Split(valid, "\n")[:2], "\n"),
		"malformed":                "10 1 / / ro",
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkGuestMountinfo([]byte(invalid)); err == nil {
				t.Fatal("unsafe mount layout accepted")
			}
		})
	}
}
