package workload

import (
	"fmt"
	"time"
)

type Spec struct {
	Command    string
	Args       []string
	WorkingDir string
	Env        []string
	Timeout    time.Duration

	Resources ResourceSpec
}

type ResourceSpec struct {
	MemoryBytes   int64
	MaxProcesses  int
	CPUMilliCores int
}

func (s Spec) Validate() error {
	if s.Command == "" {
		return fmt.Errorf("workload command must not be empty")
	}
	if s.Timeout < 0 {
		return fmt.Errorf("workload timeout must not be negative")
	}
	if s.Resources.MemoryBytes < 0 {
		return fmt.Errorf("memory limit must not be negative")
	}
	if s.Resources.MaxProcesses < 0 {
		return fmt.Errorf("process limit must not be negative")
	}
	if s.Resources.CPUMilliCores < 0 {
		return fmt.Errorf("CPU limit must not be negative")
	}
	return nil
}

func cloneSpec(spec Spec) Spec {
	cloned := spec

	cloned.Args = append([]string(nil), spec.Args...)
	cloned.Env = append([]string(nil), spec.Env...)

	return cloned
}
