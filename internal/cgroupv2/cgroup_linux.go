package cgroupv2

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/workload"
)

const cpuPeriodMicros int64 = 100_000

type Group struct {
	path string
}

func Create(
	root string,
	name string,
	resources workload.ResourceSpec,
) (*Group, error) {
	if root == "" {
		return nil, fmt.Errorf("cgroup root must not be empty")
	}

	if err := validateName(name); err != nil {
		return nil, err
	}

	path := filepath.Join(root, name)

	if err := os.Mkdir(path, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup %q: %w", path, err)
	}

	success := false

	defer func() {
		if !success {
			_ = os.Remove(path)
		}
	}()

	if resources.MemoryBytes > 0 {
		if err := writeControl(
			filepath.Join(path, "memory.max"),
			strconv.FormatInt(resources.MemoryBytes, 10),
		); err != nil {
			return nil, fmt.Errorf("set memory limit: %w", err)
		}

		if err := writeControl(
			filepath.Join(path, "memory.swap.max"),
			"0",
		); err != nil {
			return nil, fmt.Errorf("disable workload swap: %w", err)
		}
	}

	if resources.MaxProcesses > 0 {
		if err := writeControl(
			filepath.Join(path, "pids.max"),
			strconv.Itoa(resources.MaxProcesses),
		); err != nil {
			return nil, fmt.Errorf("set process limit: %w", err)
		}
	}

	if resources.CPUMilliCores > 0 {
		cpuMax, err := cpuMaxValue(resources.CPUMilliCores)
		if err != nil {
			return nil, fmt.Errorf("set CPU limit: %w", err)
		}

		if err := writeControl(
			filepath.Join(path, "cpu.max"),
			cpuMax,
		); err != nil {
			return nil, fmt.Errorf("set CPU limit: %w", err)
		}
	}

	success = true

	return &Group{
		path: path,
	}, nil
}

func (g *Group) Open() (*os.File, error) {
	f, err := os.Open(g.path)
	if err != nil {
		return nil, fmt.Errorf("open cgroup %q: %w", g.path, err)
	}

	return f, nil
}

func (g *Group) Remove() error {
	if err := os.Remove(g.path); err != nil {
		return fmt.Errorf("remove cgroup %q: %w", g.path, err)
	}

	return nil
}

func (g *Group) Path() string {
	return g.path
}

func writeControl(path string, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(value); err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}

	return nil
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("cgroup name must not be empty")
	}

	for _, r := range name {
		valid :=
			r >= 'a' && r <= 'z' ||
				r >= 'A' && r <= 'Z' ||
				r >= '0' && r <= '9' ||
				r == '-' ||
				r == '_' ||
				r == '.'

		if !valid {
			return fmt.Errorf(
				"invalid character %q in cgroup name %q",
				r,
				name,
			)
		}
	}

	if name == "." || name == ".." {
		return fmt.Errorf("invalid cgroup name %q", name)
	}

	return nil
}

func (g *Group) Kill() error {
	if err := writeControl(
		filepath.Join(g.path, "cgroup.kill"),
		"1",
	); err != nil {
		return fmt.Errorf("kill cgroup %q: %w", g.path, err)
	}

	return nil
}

func (g *Group) WaitEmpty(ctx context.Context) error {
	const pollInterval = 10 * time.Millisecond

	eventsPath := filepath.Join(g.path, "cgroup.events")

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		populated, err := readPopulated(eventsPath)
		if err != nil {
			return fmt.Errorf(
				"read cgroup populated state %q: %w",
				g.path,
				err,
			)
		}

		if !populated {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf(
				"wait for cgroup %q to become empty: %w",
				g.path,
				ctx.Err(),
			)

		case <-ticker.C:
		}
	}
}

func readPopulated(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read %q: %w", path, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)

		if len(fields) != 2 || fields[0] != "populated" {
			continue
		}

		switch fields[1] {
		case "0":
			return false, nil

		case "1":
			return true, nil

		default:
			return false, fmt.Errorf(
				"invalid populated value %q",
				fields[1],
			)
		}
	}

	return false, fmt.Errorf("populated field not found")
}

func cpuMaxValue(milliCores int) (string, error) {
	if milliCores <= 0 {
		return "", fmt.Errorf(
			"CPU millicores must be positive",
		)
	}

	quotaMicros :=
		int64(milliCores) * cpuPeriodMicros / 1000

	if quotaMicros < 1000 {
		return "", fmt.Errorf(
			"CPU limit %d millicores is too small",
			milliCores,
		)
	}

	return fmt.Sprintf(
		"%d %d",
		quotaMicros,
		cpuPeriodMicros,
	), nil
}
