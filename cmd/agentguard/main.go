package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/runner"
	agruntime "github.com/Oreki0504/AgentGuard/internal/runtime"
	"github.com/Oreki0504/AgentGuard/internal/runtime/sandbox/linux"
	"github.com/Oreki0504/AgentGuard/internal/workload"
)

type environmentFlags []string

func (e *environmentFlags) String() string         { return "explicit KEY=value (repeatable)" }
func (e *environmentFlags) Set(value string) error { *e = append(*e, value); return nil }

func main() {

	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: agentguard run [--timeout duration] -- <command> [args...]")
		os.Exit(2)
	}

	runFlags := flag.NewFlagSet("run", flag.ContinueOnError)

	sandbox := runFlags.Bool("sandbox", false, "run with namespaces, filesystem isolation and delegated cgroup")

	cgroupRoot := runFlags.String("cgroup-root", os.Getenv("AGENTGUARD_CGROUP_ROOT"), "delegated cgroup v2 root")

	launcher := runFlags.String("launcher", "/usr/local/libexec/agentguard-launcher", "trusted installed launcher")

	workspace := runFlags.String("workspace", "", "explicit host workspace exposed at /workspace")

	readOnly := runFlags.Bool("workspace-readonly", true, "expose workspace read-only")

	scratch := runFlags.String("scratch", "", "explicit writable host directory exposed at /scratch")

	workingDir := runFlags.String("cwd", "", "working directory (guest path in sandbox mode)")

	startupTimeout := runFlags.Duration("startup-timeout", linux.DefaultStartupTimeout, "bounded sandbox startup deadline")

	memory := runFlags.Int64("memory", 128*1024*1024, "sandbox memory limit in bytes")

	pids := runFlags.Int("pids", 128, "sandbox process/thread limit including trusted launcher")

	cpu := runFlags.Int("cpu", 1000, "sandbox CPU limit in millicores")

	var env environmentFlags

	runFlags.Var(&env, "env", "explicit KEY=value (repeatable)")

	timeout := runFlags.Duration(
		"timeout",
		0,
		"execution timeout",
	)

	if err := runFlags.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	commandArgs := runFlags.Args()

	if len(commandArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agentguard run [--timeout duration] -- <command> [args...]")
		os.Exit(2)
	}

	command := commandArgs[0]
	args := commandArgs[1:]

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	var result runner.Result
	var err error
	if *sandbox {
		files, fileErr := linux.ShellFiles()
		if fileErr != nil {
			fmt.Fprintln(os.Stderr, fileErr)
			os.Exit(1)
		}
		cfg := &agruntime.SandboxConfig{Launcher: *launcher, Files: files, StartupTimeout: *startupTimeout}
		for _, exposure := range []struct {
			source, target string
			ro             bool
		}{{*workspace, "/workspace", *readOnly}, {*scratch, "/scratch", false}} {
			if exposure.source != "" {
				source, pathErr := filepath.Abs(exposure.source)
				if pathErr != nil {
					fmt.Fprintln(os.Stderr, pathErr)
					os.Exit(2)
				}
				cfg.Mounts = append(cfg.Mounts, linux.BindMount{Source: source, Target: exposure.target, ReadOnly: exposure.ro})
			}
		}
		rt, newErr := agruntime.New(agruntime.Config{CgroupRoot: *cgroupRoot, Sandbox: cfg})
		if newErr != nil {
			fmt.Fprintln(os.Stderr, newErr)
			os.Exit(1)
		}
		w, newErr := workload.New(fmt.Sprintf("cli-%d-%d", os.Getpid(), time.Now().UnixNano()), workload.Spec{
			Command: command, Args: args, WorkingDir: *workingDir, Env: env, Timeout: *timeout,
			Resources: workload.ResourceSpec{MemoryBytes: *memory, MaxProcesses: *pids, CPUMilliCores: *cpu}})
		if newErr != nil {
			fmt.Fprintln(os.Stderr, newErr)
			os.Exit(2)
		}
		result, err = rt.Run(ctx, w)
	} else {
		if *workspace != "" || *scratch != "" {
			fmt.Fprintln(os.Stderr, "workspace and scratch require --sandbox")
			os.Exit(2)
		}
		result, err = runner.Run(ctx, runner.Request{Command: command, Args: args, Timeout: *timeout, WorkingDir: *workingDir, Env: env})
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "agentguard: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprint(os.Stdout, result.Stdout)
	fmt.Fprint(os.Stderr, result.Stderr)
	if result.StdoutTruncated {
		fmt.Fprintln(os.Stderr,
			"agentguard: warning: stdout was truncated")
	}

	if result.StderrTruncated {
		fmt.Fprintln(os.Stderr,
			"agentguard: warning: stderr was truncated")
	}

	if result.TimedOut {
		fmt.Fprintf(
			os.Stderr,
			"agentguard: command timed out after %v\n",
			result.Duration,
		)
		os.Exit(124)
	}

	if result.Canceled {
		fmt.Fprintln(os.Stderr, "agentguard: canceled")
		os.Exit(130)
	}

	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}
}
