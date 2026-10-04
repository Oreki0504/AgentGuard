package cgroupv2

import (
	"context"
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
