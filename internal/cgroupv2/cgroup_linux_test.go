package cgroupv2

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

	"github.com/Oreki0504/AgentGuard/internal/workload"
)

func TestCreateAndRemove(t *testing.T) {
	root := t.TempDir()

	group, err := Create(
		root,
		"test-workload",
		workload.ResourceSpec{},
	)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	wantPath := filepath.Join(root, "test-workload")

	if group.Path() != wantPath {
		t.Fatalf(
			"unexpected cgroup path: got %q, want %q",
			group.Path(),
			wantPath,
		)
	}

	f, err := group.Open()
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	f.Close()

	if err := group.Remove(); err != nil {
		t.Fatalf("Remove returned error: %v", err)
	}

	if _, err := os.Stat(wantPath); !os.IsNotExist(err) {
		t.Fatalf("expected cgroup directory to be removed")
	}
}

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{
			name:    "simple",
			value:   "workload-001",
			wantErr: false,
		},
		{
			name:    "underscore and dot",
			value:   "agentguard_test.1",
			wantErr: false,
		},
		{
			name:    "empty",
			value:   "",
			wantErr: true,
		},
		{
			name:    "parent directory",
			value:   "..",
			wantErr: true,
		},
		{
			name:    "path traversal",
			value:   "../../etc",
			wantErr: true,
		},
		{
			name:    "slash",
			value:   "foo/bar",
			wantErr: true,
		},
		{
			name:    "space",
			value:   "foo bar",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateName(tt.value)

			if tt.wantErr && err == nil {
				t.Fatal("expected validation error")
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestWriteControl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control")

	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("failed to create control file: %v", err)
	}

	if err := writeControl(path, "123"); err != nil {
		t.Fatalf("writeControl returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read control file: %v", err)
	}

	if string(data) != "123" {
		t.Fatalf(
			"unexpected control value: got %q, want %q",
			string(data),
			"123",
		)
	}
}

func TestCreateCgroupIntegration(t *testing.T) {
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Skip("AGENTGUARD_CGROUP_ROOT is not set")
	}

	name := fmt.Sprintf(
		"agentguard-test-%d",
		os.Getpid(),
	)

	group, err := Create(
		root,
		name,
		workload.ResourceSpec{
			MemoryBytes:   64 * 1024 * 1024,
			MaxProcesses:  16,
			CPUMilliCores: 500,
		},
	)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	t.Cleanup(func() {
		_ = group.Remove()
	})

	memoryData, err := os.ReadFile(
		filepath.Join(group.Path(), "memory.max"),
	)
	if err != nil {
		t.Fatalf("failed to read memory.max: %v", err)
	}

	wantMemory := strconv.FormatInt(64*1024*1024, 10)

	if strings.TrimSpace(string(memoryData)) != wantMemory {
		t.Fatalf(
			"unexpected memory.max: got %q, want %q",
			strings.TrimSpace(string(memoryData)),
			wantMemory,
		)
	}

	swapData, err := os.ReadFile(
		filepath.Join(group.Path(), "memory.swap.max"),
	)
	if err != nil {
		t.Fatalf("failed to read memory.swap.max: %v", err)
	}

	if strings.TrimSpace(string(swapData)) != "0" {
		t.Fatalf(
			"unexpected memory.swap.max: got %q, want %q",
			strings.TrimSpace(string(swapData)),
			"0",
		)
	}

	pidsData, err := os.ReadFile(
		filepath.Join(group.Path(), "pids.max"),
	)
	if err != nil {
		t.Fatalf("failed to read pids.max: %v", err)
	}

	if strings.TrimSpace(string(pidsData)) != "16" {
		t.Fatalf(
			"unexpected pids.max: got %q, want %q",
			strings.TrimSpace(string(pidsData)),
			"16",
		)
	}

	cpuData, err := os.ReadFile(
		filepath.Join(group.Path(), "cpu.max"),
	)
	if err != nil {
		t.Fatalf("failed to read cpu.max: %v", err)
	}

	if strings.TrimSpace(string(cpuData)) != "50000 100000" {
		t.Fatalf(
			"unexpected cpu.max: got %q, want %q",
			strings.TrimSpace(string(cpuData)),
			"50000 100000",
		)
	}

	f, err := group.Open()
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	f.Close()

	if _, err := os.Stat(
		filepath.Join(group.Path(), "cgroup.kill"),
	); err != nil {
		t.Fatalf("cgroup.kill is unavailable: %v", err)
	}
}

func TestReadPopulated(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
		wantErr bool
	}{
		{
			name:    "empty",
			content: "populated 0\nfrozen 0\n",
			want:    false,
		},
		{
			name:    "populated",
			content: "populated 1\nfrozen 0\n",
			want:    true,
		},
		{
			name:    "missing populated",
			content: "frozen 0\n",
			wantErr: true,
		},
		{
			name:    "invalid populated",
			content: "populated 123\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cgroup.events")

			if err := os.WriteFile(
				path,
				[]byte(tt.content),
				0o644,
			); err != nil {
				t.Fatalf("write test events file: %v", err)
			}

			got, err := readPopulated(path)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Fatalf(
					"unexpected populated state: got %v, want %v",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestKillAndWaitEmptyIntegration(t *testing.T) {
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Skip("AGENTGUARD_CGROUP_ROOT is not set")
	}

	name := fmt.Sprintf(
		"agentguard-kill-test-%d",
		os.Getpid(),
	)

	group, err := Create(
		root,
		name,
		workload.ResourceSpec{
			MemoryBytes:  64 * 1024 * 1024,
			MaxProcesses: 16,
		},
	)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	t.Cleanup(func() {
		_ = group.Remove()
	})

	cgroupFile, err := group.Open()
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer cgroupFile.Close()

	cmd := exec.Command("/bin/sleep", "30")

	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroupFile.Fd()),
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	// Always reap our direct child.
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	populated, err := readPopulated(
		filepath.Join(group.Path(), "cgroup.events"),
	)
	if err != nil {
		t.Fatalf("read populated state: %v", err)
	}

	if !populated {
		t.Fatal("expected cgroup to be populated")
	}

	if err := group.Kill(); err != nil {
		t.Fatalf("Kill returned error: %v", err)
	}

	waitCtx, cancel := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancel()

	if err := group.WaitEmpty(waitCtx); err != nil {
		t.Fatalf("WaitEmpty returned error: %v", err)
	}
}

func TestCPUMaxValue(t *testing.T) {
	tests := []struct {
		name       string
		milliCores int
		want       string
		wantErr    bool
	}{
		{
			name:       "one CPU",
			milliCores: 1000,
			want:       "100000 100000",
		},
		{
			name:       "half CPU",
			milliCores: 500,
			want:       "50000 100000",
		},
		{
			name:       "two CPUs",
			milliCores: 2000,
			want:       "200000 100000",
		},
		{
			name:       "minimum supported",
			milliCores: 10,
			want:       "1000 100000",
		},
		{
			name:       "too small",
			milliCores: 1,
			wantErr:    true,
		},
		{
			name:       "zero",
			milliCores: 0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := cpuMaxValue(tt.milliCores)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf(
					"cpuMaxValue returned error: %v",
					err,
				)
			}

			if got != tt.want {
				t.Fatalf(
					"unexpected cpu.max value: got %q, want %q",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestCPUThrottlingIntegration(t *testing.T) {
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Skip("AGENTGUARD_CGROUP_ROOT is not set")
	}

	name := fmt.Sprintf(
		"agentguard-cpu-test-%d",
		os.Getpid(),
	)

	group, err := Create(
		root,
		name,
		workload.ResourceSpec{
			CPUMilliCores: 100,
		},
	)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	t.Cleanup(func() {
		_ = group.Kill()

		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()

		_ = group.WaitEmpty(ctx)
		_ = group.Remove()
	})

	cgroupFile, err := group.Open()
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer cgroupFile.Close()

	cmd := exec.Command(
		"/bin/sh",
		"-c",
		"while :; do :; done",
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroupFile.Fd()),
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start CPU workload: %v", err)
	}

	// Give the workload several 100 ms CPU periods so that
	// the kernel has an opportunity to throttle it.
	time.Sleep(600 * time.Millisecond)

	if err := group.Kill(); err != nil {
		t.Fatalf("Kill returned error: %v", err)
	}

	// Reap our direct child.
	_ = cmd.Wait()

	waitCtx, cancel := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancel()

	if err := group.WaitEmpty(waitCtx); err != nil {
		t.Fatalf("WaitEmpty returned error: %v", err)
	}

	nrThrottled, err := readUintField(
		filepath.Join(group.Path(), "cpu.stat"),
		"nr_throttled",
	)
	if err != nil {
		t.Fatalf("read nr_throttled: %v", err)
	}

	if nrThrottled == 0 {
		t.Fatal(
			"expected CPU workload to be throttled, got nr_throttled=0",
		)
	}
}

func readUintField(
	path string,
	key string,
) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf(
			"read %q: %w",
			path,
			err,
		)
	}

	for _, line := range strings.Split(
		string(data),
		"\n",
	) {
		fields := strings.Fields(line)

		if len(fields) != 2 || fields[0] != key {
			continue
		}

		value, err := strconv.ParseUint(
			fields[1],
			10,
			64,
		)
		if err != nil {
			return 0, fmt.Errorf(
				"parse %s value %q: %w",
				key,
				fields[1],
				err,
			)
		}

		return value, nil
	}

	return 0, fmt.Errorf(
		"%s field not found",
		key,
	)
}

func TestProcessLimitIntegration(t *testing.T) {
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Skip("AGENTGUARD_CGROUP_ROOT is not set")
	}

	name := fmt.Sprintf(
		"agentguard-pids-test-%d",
		os.Getpid(),
	)

	const maxProcesses = 8

	group, err := Create(
		root,
		name,
		workload.ResourceSpec{
			MaxProcesses: maxProcesses,
		},
	)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	t.Cleanup(func() {
		_ = group.Kill()

		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()

		_ = group.WaitEmpty(ctx)
		_ = group.Remove()
	})

	cgroupFile, err := group.Open()
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer cgroupFile.Close()

	cmd := exec.Command(
		"/bin/sh",
		"-c",
		`
i=0
while [ "$i" -lt 64 ]; do
	/bin/sleep 30 &
	i=$((i + 1))
done
wait
`,
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroupFile.Fd()),
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start process-abuse workload: %v", err)
	}

	// Give the workload time to hit pids.max.
	time.Sleep(500 * time.Millisecond)

	maxEvents, err := readUintField(
		filepath.Join(group.Path(), "pids.events"),
		"max",
	)
	if err != nil {
		t.Fatalf("read pids.events max: %v", err)
	}

	if maxEvents == 0 {
		t.Fatal(
			"expected pids.max to reject at least one process creation",
		)
	}

	if err := group.Kill(); err != nil {
		t.Fatalf("Kill returned error: %v", err)
	}

	_ = cmd.Wait()

	waitCtx, cancel := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancel()

	if err := group.WaitEmpty(waitCtx); err != nil {
		t.Fatalf("WaitEmpty returned error: %v", err)
	}
}

func TestMemoryLimitIntegration(t *testing.T) {
	root := os.Getenv("AGENTGUARD_CGROUP_ROOT")
	if root == "" {
		t.Skip("AGENTGUARD_CGROUP_ROOT is not set")
	}

	name := fmt.Sprintf(
		"agentguard-memory-test-%d",
		os.Getpid(),
	)

	const memoryLimit = 64 * 1024 * 1024

	group, err := Create(
		root,
		name,
		workload.ResourceSpec{
			MemoryBytes: memoryLimit,
		},
	)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	t.Cleanup(func() {
		_ = group.Kill()

		ctx, cancel := context.WithTimeout(
			context.Background(),
			time.Second,
		)
		defer cancel()

		_ = group.WaitEmpty(ctx)
		_ = group.Remove()
	})

	cgroupFile, err := group.Open()
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	defer cgroupFile.Close()

	cmd := exec.Command(
		"/usr/bin/python3",
		"-c",
		`
x = bytearray(256 * 1024 * 1024)
for i in range(0, len(x), 4096):
    x[i] = 1
print("unexpectedly allocated memory")
`,
	)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    int(cgroupFile.Fd()),
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start memory-abuse workload: %v", err)
	}

	// Observe how the process terminates instead of assuming an OOM kill.
	waitErr := cmd.Wait()

	if waitErr == nil {
		t.Fatal("expected memory-abuse workload to be killed")
	}

	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) {
		t.Fatalf(
			"unexpected wait error type: %v",
			waitErr,
		)
	}

	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf(
			"unexpected process status: %v",
			exitErr.Sys(),
		)
	}

	if !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf(
			"unexpected process termination: %v",
			status,
		)
	}

	waitCtx, cancel := context.WithTimeout(
		context.Background(),
		2*time.Second,
	)
	defer cancel()

	if err := group.WaitEmpty(waitCtx); err != nil {
		t.Fatalf("WaitEmpty returned error: %v", err)
	}

	oomKills, err := readUintField(
		filepath.Join(group.Path(), "memory.events"),
		"oom_kill",
	)
	if err != nil {
		t.Fatalf("read memory.events oom_kill: %v", err)
	}

	if oomKills == 0 {
		t.Fatal(
			"expected memory limit to trigger an OOM kill",
		)
	}

	peakData, err := os.ReadFile(
		filepath.Join(group.Path(), "memory.peak"),
	)
	if err != nil {
		t.Fatalf("read memory.peak: %v", err)
	}

	memoryPeak, err := strconv.ParseInt(
		strings.TrimSpace(string(peakData)),
		10,
		64,
	)
	if err != nil {
		t.Fatalf(
			"parse memory.peak %q: %v",
			string(peakData),
			err,
		)
	}

	if memoryPeak > memoryLimit {
		t.Fatalf(
			"memory peak exceeded limit: got %d, limit %d",
			memoryPeak,
			memoryLimit,
		)
	}

	swapPeakData, err := os.ReadFile(
		filepath.Join(group.Path(), "memory.swap.peak"),
	)
	if err != nil {
		t.Fatalf("read memory.swap.peak: %v", err)
	}

	swapPeak, err := strconv.ParseInt(
		strings.TrimSpace(string(swapPeakData)),
		10,
		64,
	)
	if err != nil {
		t.Fatalf(
			"parse memory.swap.peak %q: %v",
			string(swapPeakData),
			err,
		)
	}

	if swapPeak != 0 {
		t.Fatalf(
			"expected no swap usage, got %d bytes",
			swapPeak,
		)
	}

	currentData, err := os.ReadFile(
		filepath.Join(group.Path(), "memory.current"),
	)
	if err != nil {
		t.Fatalf("read memory.current: %v", err)
	}

	current, err := strconv.ParseInt(
		strings.TrimSpace(string(currentData)),
		10,
		64,
	)
	if err != nil {
		t.Fatalf(
			"parse memory.current %q: %v",
			string(currentData),
			err,
		)
	}

	if current > memoryLimit {
		t.Fatalf(
			"memory usage remained above limit: got %d, limit %d",
			current,
			memoryLimit,
		)
	}
}
