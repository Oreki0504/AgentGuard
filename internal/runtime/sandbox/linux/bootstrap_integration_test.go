package linux

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/cgroupv2"
	"github.com/Oreki0504/AgentGuard/internal/runner"
	"github.com/Oreki0504/AgentGuard/internal/workload"
)

const phase2cProbe = "/usr/local/libexec/agentguard-phase2c-probe"

// The test driver must already be in the intended policy namespace, with
// ordinary host credentials. Entering via unprivileged aa-exec can hide an
// outer stacked domain in the namespace-local label (first confined failure).
func checkPhase2cEntry(namespace string) error {
	if os.Getuid() == 0 || os.Geteuid() != os.Getuid() || os.Getegid() != os.Getgid() {
		return fmt.Errorf("test must run with ordinary, matching host credentials")
	}
	for name, expected := range map[string]string{
		".ns_name": namespace, ".stacked": "no", ".ns_stacked": "no",
	} {
		data, err := os.ReadFile("/sys/kernel/security/apparmor/" + name)
		if err != nil || strings.TrimSpace(string(data)) != expected {
			return fmt.Errorf("AppArmor %s=%q expected=%q error=%v", name, data, expected, err)
		}
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	for _, field := range []string{
		"CapInh:\t0000000000000000\n", "CapPrm:\t0000000000000000\n",
		"CapEff:\t0000000000000000\n", "CapAmb:\t0000000000000000\n",
		"NoNewPrivs:\t0\n",
	} {
		if !strings.Contains(string(status), field) {
			return fmt.Errorf("unexpected host credentials before confined exec: %s", strings.TrimSpace(field))
		}
	}
	return nil
}

// Explicitly gated and run one case per authorization. Uses the existing
// Runner, Session, cgroup implementation, namespace/rootfs setup and PID1
// reaper; the helper entry points exist only in the Go test binary.
func TestBootstrapConfinedExec(t *testing.T) {
	ns := os.Getenv("AGENTGUARD_PHASE2C_NAMESPACE")
	if ns == "" {
		t.Skip("requires individually authorized confined Phase 2C test")
	}
	if !strings.HasPrefix(ns, "agentguard-phase2c-") || strings.ContainsAny(ns, "/:\x00") {
		t.Fatal("invalid isolated test policy namespace")
	}
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Fatal("explicit Phase 2C test requires a delegated cgroup root")
	}
	if err := checkPhase2cEntry(ns); err != nil {
		t.Fatal(err)
	}
	t.Logf("driver namespace=%s stacked=no ns_stacked=no host_uid=%d host_gid=%d", ns, os.Getuid(), os.Getgid())
	for _, name := range []string{"agentguard-bootstrap", "agentguard-phase2c-probe"} {
		built, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "bin", name))
		if err != nil {
			t.Fatal(err)
		}
		installed, err := os.ReadFile(filepath.Join("/usr/local/libexec", name))
		if err != nil || !bytes.Equal(built, installed) {
			t.Fatalf("installed %s differs from the reviewed build: %v", name, err)
		}
	}
	probe, err := OpenTrustedExecutable(phase2cProbe)
	if err != nil {
		t.Fatal(err)
	}
	probe.Close()
	for _, mode := range []string{"shell", "go", "missing-loader", "regular-stdio", "bad-stdio", "timeout", "cancel", "tracer-exit"} {
		t.Run(mode, func(t *testing.T) {
			files, err := ShellFiles()
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing-loader" {
				files = files[:1]
			}
			if mode == "go" {
				files = append(files, File{Source: phase2cProbe, Target: "/bin/probe-guest"})
			}
			rootfs, err := os.MkdirTemp("/tmp", "agentguard-rootfs-phase2c-")
			if err != nil {
				t.Fatal(err)
			}
			// Do not recursively remove, or release before confirmed empty.
			group, err := cgroupv2.Create(root, fmt.Sprintf("phase2c-%d-%s", os.Getpid(), mode),
				workload.ResourceSpec{MemoryBytes: 256 * 1024 * 1024, MaxProcesses: 128, CPUMilliCores: 1000})
			if err != nil {
				os.Remove(rootfs)
				t.Fatal(err)
			}
			t.Logf("case=%s cgroup=%s rootfs=%s", mode, group.Path(), rootfs)
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := group.Kill(); err != nil {
					t.Errorf("cleanup kill: %v", err)
					return
				}
				if err := group.WaitEmpty(ctx); err != nil {
					t.Errorf("preserve cgroup=%s rootfs=%s: %v", group.Path(), rootfs, err)
					return
				}
				if err := os.Remove(rootfs); err != nil {
					t.Errorf("rootfs cleanup: %v", err)
					return
				}
				if err := group.Remove(); err != nil {
					t.Errorf("cgroup cleanup: %v", err)
					return
				}
				t.Log("confirmed cgroup empty, then released rootfs and cgroup")
			}()
			c := Config{Version: Version, WorkloadID: mode, Rootfs: rootfs, WorkingDir: "/",
				Argv:  []string{"/bin/sh", "-c", "test \"$(/bin/sh -c 'printf child')\" = child"},
				Files: files, StartupTimeout: 3 * time.Second}
			if mode == "go" {
				c.Argv = []string{"/bin/probe-guest", "-test.run=^TestBootstrapConfinedGuest$"}
				c.Env = []string{"AGENTGUARD_PHASE2C_GUEST=1"}
			}
			bootstrap, err := OpenTrustedExecutable(BootstrapPath)
			if err != nil {
				t.Fatal(err)
			}
			session, err := Prepare(c, bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			groupFile, err := group.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer groupFile.Close()
			ready := 0
			// Match production path attachment: exec the approved entry
			// directly as the ordinary user, with no change_profile request.
			req := runner.Request{Command: phase2cProbe,
				Args:       []string{"-test.run=^TestBootstrapConfinedLauncherHelper$"},
				Env:        []string{"AGENTGUARD_PHASE2C_HELPER=launcher"},
				Timeout:    6 * time.Second,
				ExtraFiles: session.ExtraFiles(),
				Startup:    &runner.Startup{Timeout: c.StartupTimeout, Wait: session.WaitReady},
				Linux:      runner.LinuxOptions{UseCgroupFD: true, CgroupFD: int(groupFile.Fd())},
				Hooks: runner.Hooks{
					OnStarted: func(pid int) error {
						t.Logf("confined launcher host_pid=%d", pid)
						return session.Started(pid)
					},
					OnReady:       func(int) error { ready++; return nil },
					OnTerminating: func(runner.TerminationReason) error { return group.Kill() },
				},
			}
			result, runErr := runner.Run(context.Background(), req)
			t.Logf("READY=%d launcher_exit=%d error=%v\nstdout=%s\nstderr=%s",
				ready, result.ExitCode, runErr, result.Stdout, result.Stderr)
			expectedFailure := map[string]string{
				"missing-loader": "agentguard-bootstrap: guest exec",
				"bad-stdio":      "agentguard-bootstrap: stdio access",
				"timeout":        "guest exec confirmation timed out",
				"cancel":         "guest exec confirmation canceled",
				"tracer-exit":    "test tracer exiting after CONT",
			}[mode]
			if expectedFailure != "" {
				if runErr == nil || ready != 0 || !strings.Contains(result.Stderr, expectedFailure) {
					t.Fatalf("startup did not fail closed at expected stage %q", expectedFailure)
				}
				return
			}
			if runErr != nil || ready != 1 || result.ExitCode != 0 {
				t.Fatal("confined exec evidence did not complete successfully")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			code, err := session.WaitResult(ctx)
			if err != nil || code != 0 {
				t.Fatalf("guest result=%d error=%v", code, err)
			}
			for _, marker := range []string{"PARENT label=agentguard-launcher (enforce)",
				"PID1 rootfs verified", "trace SETOPTIONS", "trace CONT",
				"trace EVENT_EXEC", "trace DETACH", "Guest exec confirmed and resumed"} {
				if !strings.Contains(result.Stdout, marker) {
					t.Errorf("missing evidence %q", marker)
				}
			}
		})
	}
}

func TestBootstrapConfinedLauncherHelper(t *testing.T) {
	if os.Getenv("AGENTGUARD_PHASE2C_HELPER") != "launcher" {
		return
	}
	label, err := os.ReadFile("/proc/self/attr/apparmor/current")
	if err != nil || string(label) != "agentguard-launcher (enforce)\n" {
		fmt.Fprintf(os.Stderr, "unexpected actual parent label %q: %v\n", label, err)
		os.Exit(125)
	}
	for _, name := range []string{".stacked", ".ns_stacked"} {
		data, err := os.ReadFile("/sys/kernel/security/apparmor/" + name)
		if err != nil || strings.TrimSpace(string(data)) != "no" {
			fmt.Fprintf(os.Stderr, "unexpected parent AppArmor %s=%q: %v\n", name, data, err)
			os.Exit(125)
		}
	}
	fmt.Printf("PARENT label=%s", label)
	fmt.Println("PARENT stacked=no ns_stacked=no")
	config := os.NewFile(3, "config")
	var c Config
	if err := readFrame(config, &c, MaxConfigSize); err != nil {
		os.Exit(125)
	}
	if err := validateBootstrapConfig(c); err != nil {
		os.Exit(125)
	}
	if _, err := config.Seek(0, 0); err != nil {
		os.Exit(125)
	}
	for fd := 3; fd < 6+len(c.Files)+len(c.Mounts); fd++ {
		syscall.CloseOnExec(fd)
	}
	// Same namespace setup as the installed Go launcher. Only the test's init
	// selector differs; no alternative selector is compiled into production.
	child := exec.Command(phase2cProbe, "-test.run=^TestBootstrapConfinedInitHelper$")
	child.Env = []string{"AGENTGUARD_PHASE2C_HELPER=init"}
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = namespaceAttributes()
	for fd := 3; fd < 6+len(c.Files)+len(c.Mounts); fd++ {
		child.ExtraFiles = append(child.ExtraFiles, os.NewFile(uintptr(fd), "probe-fd"))
	}
	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start Go PID1: %v\n", err)
		os.Exit(125)
	}
	for _, file := range child.ExtraFiles {
		file.Close()
	}
	if err := child.Wait(); err != nil {
		os.Exit(125)
	}
	os.Exit(0)
}

func TestBootstrapConfinedInitHelper(t *testing.T) {
	if os.Getenv("AGENTGUARD_PHASE2C_HELPER") != "init" {
		return
	}
	runtime.LockOSThread()
	// This locked thread is terminated with the test process, never reused.
	status := os.NewFile(4, "status")
	failed := func(stage string, err error) {
		fmt.Fprintf(os.Stderr, "%s: %v\n", stage, err)
		os.Exit(reportFailure(status, "init", stage))
	}
	if os.Getpid() != 1 {
		failed("expected Go namespace PID1", nil)
	}
	if err := prctl(4, 0); err != nil {
		failed("protect PID1 descriptors", err)
	}
	var c Config
	config := os.NewFile(3, "config")
	if err := readFrame(config, &c, MaxConfigSize); err != nil {
		failed("read config", err)
	}
	for fd := 3; fd < 6+len(c.Files)+len(c.Mounts); fd++ {
		syscall.CloseOnExec(fd)
	}
	if err := closeVerified(config); err != nil {
		failed("close host config", err)
	}
	var sources []*os.File
	for i := 0; i < len(c.Files)+len(c.Mounts); i++ {
		sources = append(sources, os.NewFile(uintptr(5+i), "source"))
	}
	bootstrap := os.NewFile(uintptr(5+len(sources)), "bootstrap")
	if err := prepareBootstrapRootfs(c, sources, bootstrap); err != nil {
		failed("bootstrap rootfs", err)
	}
	fmt.Println("PID1 rootfs verified")
	contract, err := newBootstrapConfig(c, "/tmp")
	if err != nil {
		failed("bootstrap contract", err)
	}
	streams := []*os.File{os.Stdin, os.Stdout, os.Stderr, contract}
	if c.WorkloadID == "bad-stdio" {
		// A closed stdin may fail in libc's secure startup before C main.
		// Keep fd 0 present but unreadable so C's access check is exercised.
		file, err := os.OpenFile("/tmp/bad-stdin", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			failed("bad stdio fixture", err)
		}
		defer file.Close()
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFL, 0)
		if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_WRONLY {
			failed("bad stdio fixture access", errno)
		}
		streams[0] = file
	}
	if c.WorkloadID == "regular-stdio" {
		file, err := os.OpenFile("/tmp/stdio", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			failed("regular stdio", err)
		}
		defer file.Close()
		streams[0], streams[1] = file, file
	}
	if err := dropMountAuthority(); err != nil {
		failed("drop capabilities", err)
	}
	signals := make(chan os.Signal, 16)
	signal.Notify(signals, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	process, err := os.StartProcess(bootstrapEntry, []string{bootstrapEntry}, &os.ProcAttr{
		Dir: "/", Env: []string{}, Files: streams, Sys: &syscall.SysProcAttr{Ptrace: true, Setpgid: true},
	})
	if err != nil {
		failed("start traced bootstrap", err)
	}
	pid := process.Pid
	process.Release()
	if err := closeVerified(contract); err != nil {
		failed("close parent contract", err)
	}
	ops := kernelTraceOps()
	actual := ops
	tid := syscall.Gettid()
	ops.wait = func(want int, status *syscall.WaitStatus, flags int, usage *syscall.Rusage) (int, error) {
		if syscall.Gettid() != tid {
			return 0, fmt.Errorf("tracer OS thread changed")
		}
		got, err := actual.wait(want, status, flags, usage)
		if got != 0 {
			fmt.Printf("trace wait4 pid=%d status=%#x error=%v\n", got, uint32(*status), err)
		}
		return got, err
	}
	ops.options = func(pid, flags int) error {
		err := actual.options(pid, flags)
		fmt.Printf("trace SETOPTIONS pid=%d flags=%#x error=%v\n", pid, flags, err)
		return err
	}
	ops.resume = func(pid, signal int) error {
		if c.WorkloadID == "timeout" || c.WorkloadID == "cancel" {
			fmt.Println("test Bootstrap held at initial exec stop")
			if c.WorkloadID == "cancel" {
				return syscall.Kill(os.Getpid(), syscall.SIGTERM)
			}
			return nil
		}
		err := actual.resume(pid, signal)
		fmt.Printf("trace CONT pid=%d error=%v\n", pid, err)
		if err == nil && c.WorkloadID == "tracer-exit" {
			fmt.Fprintln(os.Stderr, "test tracer exiting after CONT")
			os.Exit(125)
		}
		return err
	}
	ops.event = func(pid int) (uint, error) {
		former, err := actual.event(pid)
		fmt.Printf("trace EVENT_EXEC pid=%d former_tid=%d error=%v\n", pid, former, err)
		return former, err
	}
	ops.detach = func(pid int) error {
		err := actual.detach(pid)
		fmt.Printf("trace DETACH pid=%d error=%v\n", pid, err)
		return err
	}
	deadline := time.Now().Add(c.StartupTimeout)
	if c.WorkloadID == "timeout" {
		deadline = time.Now().Add(100 * time.Millisecond)
	}
	if err := observeGuestExec(pid, deadline, signals, ops); err != nil {
		failed("confirm Guest exec", err)
	}
	fmt.Printf("Guest exec confirmed and resumed pid=%d tracer_tid=%d\n", pid, tid)
	if err := WriteMessage(status, Message{Version: Version, Type: "READY"}); err != nil {
		os.Exit(125)
	}
	os.Exit(reapGuest(pid, status, signals))
}

func TestBootstrapConfinedGuest(t *testing.T) {
	if os.Getenv("AGENTGUARD_PHASE2C_GUEST") != "1" {
		return
	}
	label, err := os.ReadFile("/proc/self/attr/apparmor/current")
	if err != nil || string(label) != "agentguard-launcher//workload (enforce)\n" {
		t.Fatalf("guest label %q: %v", label, err)
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		if !strings.Contains(string(data), name+":\t0000000000000000\n") {
			t.Fatalf("nonzero %s", name)
		}
	}
	if !strings.Contains(string(data), "NoNewPrivs:\t1\n") ||
		!strings.Contains(string(data), "Seccomp:\t2\n") {
		t.Fatal("missing NNP/seccomp")
	}
	if value, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 39 /* PR_GET_NO_NEW_PRIVS */, 0, 0, 0, 0, 0); errno != 0 || value != 1 {
		t.Fatal("NNP query failed")
	}
	// Go runtime creates its own epoll/eventfd descriptors after exec. Protocol
	// and host-source FDs must not survive; descriptor type/target matters.
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil || fd <= 2 {
			continue
		}
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(target, "anon_inode:") {
			t.Fatalf("unexpected inherited FD %d: %s", fd, target)
		}
	}
	if _, err := os.OpenFile("/bin/probe-guest", os.O_WRONLY, 0); err == nil {
		t.Fatal("trusted executable writable")
	}
	file, err := os.Create("/workspace/positive")
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); err != syscall.EPERM {
		if err == nil {
			syscall.Close(fd)
		}
		t.Fatalf("network syscall: %v", err)
	}
	output, err := exec.Command("/bin/sh", "-c", "printf shell-child").CombinedOutput()
	if err != nil || string(output) != "shell-child" {
		t.Fatalf("shell child %q: %v", output, err)
	}
}
