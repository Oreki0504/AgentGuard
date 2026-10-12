package runtime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/audit"
	"github.com/Oreki0504/AgentGuard/internal/cgroupv2"
	"github.com/Oreki0504/AgentGuard/internal/runner"
	"github.com/Oreki0504/AgentGuard/internal/runtime/sandbox/linux"
	"github.com/Oreki0504/AgentGuard/internal/workload"
)

type cgroupGroup interface {
	Open() (*os.File, error)
	Kill() error
	WaitEmpty(context.Context) error
	Remove() error
}

type cgroupBackend interface {
	Create(
		name string,
		resources workload.ResourceSpec,
	) (cgroupGroup, error)
}

type linuxCgroupBackend struct {
	root string
}

func (b linuxCgroupBackend) Create(
	name string,
	resources workload.ResourceSpec,
) (cgroupGroup, error) {
	return cgroupv2.Create(
		b.root,
		name,
		resources,
	)
}

const defaultCleanupTimeout = 2 * time.Second

type Config struct {
	Sandbox        *SandboxConfig
	CgroupRoot     string
	CleanupTimeout time.Duration
	Audit          audit.Sink
}

type Runtime struct {
	sandbox        *SandboxConfig
	cgroups        cgroupBackend
	execute        func(context.Context, runner.Request) (runner.Result, error)
	cleanupTimeout time.Duration
	audit          audit.Sink
}

func requestFromSpec(spec workload.Spec) runner.Request {
	return runner.Request{
		Command:    spec.Command,
		Args:       append([]string(nil), spec.Args...),
		WorkingDir: spec.WorkingDir,
		Env:        append([]string(nil), spec.Env...),
		Timeout:    spec.Timeout,
	}
}

func (r *Runtime) Run(
	ctx context.Context,
	w *workload.Workload,
) (runner.Result, error) {
	if w == nil {
		return runner.Result{}, fmt.Errorf(
			"workload must not be nil",
		)
	}

	if w.State() != workload.StatePreparing {
		return runner.Result{}, fmt.Errorf(
			"workload must be preparing before run: current state %s",
			w.State(),
		)
	}

	r.record(
		audit.EventWorkloadPreparing,
		w.ID(),
		0,
		"",
	)

	spec := w.Spec()
	var rootfs *rootfsAllocation
	var session *linux.Session

	group, err := r.cgroups.Create(
		cgroupName(w.ID()),
		spec.Resources,
	)
	if err != nil {
		failErr := r.failPreparing(
			w,
			nil,
			fmt.Errorf(
				"create workload cgroup: %w",
				err,
			),
		)

		return runner.Result{}, failErr
	}

	cgroupFile, err := group.Open()
	if err != nil {
		failErr := r.failPreparing(
			w,
			group,
			fmt.Errorf(
				"open workload cgroup: %w",
				err,
			),
		)

		return runner.Result{}, failErr
	}

	req := requestFromSpec(spec)
	if r.sandbox != nil {
		// Validate request paths before allocating host filesystem resources.
		if err := r.sandbox.launchConfig(w, "/validation-rootfs").Validate(); err != nil {
			_ = cgroupFile.Close()
			r.record(audit.EventSandboxFailed, w.ID(), 0, "config")
			return runner.Result{ExitCode: -1}, r.failPreparing(w, group, err)
		}
		rootfs, err = allocateRootfs(r.sandbox.RootfsBase)
		if err == nil {
			session, err = linux.Prepare(r.sandbox.launchConfig(w, rootfs.path))
		}
		if err != nil {
			_ = cgroupFile.Close()
			r.record(audit.EventSandboxFailed, w.ID(), 0, "config")
			return runner.Result{ExitCode: -1}, r.failPreparing(w, group, err, rootfs)
		}
		defer session.Close()
		req = runner.Request{Command: r.sandbox.Launcher, Timeout: spec.Timeout,
			ExtraFiles: session.ExtraFiles(),
			Startup:    &runner.Startup{Timeout: r.sandbox.StartupTimeout, Wait: session.WaitReady}}
	}

	req.Linux.UseCgroupFD = true
	req.Linux.CgroupFD = int(cgroupFile.Fd())

	req.Hooks.OnStarted = func(pid int) error {
		if err := w.Transition(workload.StateRunning); err != nil {
			return err
		}

		r.record(
			audit.EventWorkloadStarted,
			w.ID(),
			pid,
			"",
		)

		return nil
	}
	if session != nil {
		req.Hooks.OnReady = req.Hooks.OnStarted
		req.Hooks.OnStarted = session.Started
	}

	killedDuringRun := false

	req.Hooks.OnTerminating = func(
		reason runner.TerminationReason,
	) error {
		var errs []error

		if w.State() == workload.StateRunning {
			if err := w.Transition(
				workload.StateTerminating,
			); err != nil {
				errs = append(
					errs,
					fmt.Errorf(
						"transition workload to terminating: %w",
						err,
					),
				)
			} else {
				r.record(
					audit.EventWorkloadTerminating,
					w.ID(),
					0,
					string(reason),
				)
			}
		}

		if err := group.Kill(); err != nil {
			errs = append(
				errs,
				fmt.Errorf(
					"kill workload cgroup: %w",
					err,
				),
			)
		} else {
			killedDuringRun = true
		}

		return errors.Join(errs...)
	}

	result, runErr := r.execute(ctx, req)
	if session != nil {
		// Always release host source/config/pipe references before checking
		// cgroup emptiness and tearing down the rootfs allocation.
		session.Started(0)
		if runErr == nil && !result.TimedOut && !result.Canceled {
			resultCtx, cancel := context.WithTimeout(context.Background(), r.sandbox.StartupTimeout)
			code, statusErr := session.WaitResult(resultCtx)
			cancel()
			if statusErr != nil {
				runErr = statusErr
			} else if result.ExitCode != 0 {
				runErr = fmt.Errorf("launcher exited abnormally after result")
			} else {
				result.ExitCode = code
			}
		}
		session.Close()
		if runErr != nil || result.TimedOut || result.Canceled {
			reason := "execution"
			var failure *linux.Failure
			if errors.As(runErr, &failure) {
				reason = failure.Stage
			}
			if result.TimedOut {
				reason = "timeout"
			}
			if result.Canceled {
				reason = "canceled"
			}
			r.record(audit.EventSandboxFailed, w.ID(), 0, reason)
		}
	}

	closeErr := cgroupFile.Close()

	var errs []error

	failed :=
		runErr != nil ||
			result.TimedOut ||
			result.Canceled

	if runErr != nil {
		errs = append(
			errs,
			fmt.Errorf("runner execution failed: %w", runErr),
		)
	}

	if closeErr != nil {
		failed = true

		errs = append(
			errs,
			fmt.Errorf("close workload cgroup: %w", closeErr),
		)
	}

	if (result.TimedOut || result.Canceled) &&
		w.State() == workload.StateRunning {

		if err := w.Transition(
			workload.StateTerminating,
		); err != nil {
			failed = true

			errs = append(
				errs,
				fmt.Errorf(
					"transition workload to terminating: %w",
					err,
				),
			)
		}
	}

	cleaningErr := w.Transition(workload.StateCleaning)

	if cleaningErr != nil {
		failed = true
		errs = append(
			errs,
			fmt.Errorf(
				"transition workload to cleaning: %w",
				cleaningErr,
			),
		)
	} else {
		r.record(
			audit.EventCleanupStarted,
			w.ID(),
			0,
			"",
		)
	}

	if err := r.cleanupGroup(
		group,
		!killedDuringRun,
		rootfs,
	); err != nil {
		failed = true
		errs = append(errs, err)
		r.record(audit.EventCleanupFailed, w.ID(), 0, "resource_cleanup")
	}

	if cleaningErr == nil {
		terminalState := workload.StateFinished

		if failed {
			terminalState = workload.StateFailed
		}

		if err := w.Transition(terminalState); err != nil {
			errs = append(
				errs,
				fmt.Errorf(
					"transition workload to %s: %w",
					terminalState,
					err,
				),
			)
		} else {
			eventType := audit.EventWorkloadFinished

			if terminalState == workload.StateFailed {
				eventType = audit.EventWorkloadFailed
			}

			r.record(
				eventType,
				w.ID(),
				0,
				"",
			)
		}
	}

	return result, errors.Join(errs...)
}

func New(config Config) (*Runtime, error) {
	if config.CgroupRoot == "" {
		return nil, fmt.Errorf("cgroup root must not be empty")
	}

	auditSink := config.Audit
	if auditSink == nil {
		auditSink = audit.DiscardSink{}
	}

	if config.CleanupTimeout < 0 {
		return nil, fmt.Errorf("cleanup timeout must not be negative")
	}

	cleanupTimeout := config.CleanupTimeout
	if cleanupTimeout == 0 {
		cleanupTimeout = defaultCleanupTimeout
	}
	var sandbox *SandboxConfig
	if config.Sandbox != nil {
		copy := *config.Sandbox
		if err := validateLauncher(copy.Launcher); err != nil {
			return nil, err
		}
		if copy.RootfsBase == "" {
			copy.RootfsBase = "/tmp"
		}
		if !filepath.IsAbs(copy.RootfsBase) || filepath.Clean(copy.RootfsBase) != copy.RootfsBase {
			return nil, fmt.Errorf("rootfs base must be a clean absolute path")
		}
		if copy.StartupTimeout == 0 {
			copy.StartupTimeout = linux.DefaultStartupTimeout
		}
		if copy.StartupTimeout < 0 || copy.StartupTimeout > linux.MaxStartupTimeout {
			return nil, fmt.Errorf("invalid startup timeout")
		}
		copy.Files = append([]linux.File(nil), copy.Files...)
		copy.Mounts = append([]linux.BindMount(nil), copy.Mounts...)
		sandbox = &copy
	}

	return &Runtime{
		sandbox: sandbox,
		cgroups: linuxCgroupBackend{
			root: config.CgroupRoot,
		},
		execute:        runner.Run,
		cleanupTimeout: cleanupTimeout,
		audit:          auditSink,
	}, nil
}

func cgroupName(workloadID string) string {
	sum := sha256.Sum256([]byte(workloadID))

	return fmt.Sprintf(
		"agentguard-%x",
		sum[:16],
	)
}

func (r *Runtime) cleanupGroup(
	group cgroupGroup,
	killFirst bool,
	allocations ...*rootfsAllocation,
) error {
	cleanupCtx, cancel := context.WithTimeout(
		context.Background(),
		r.cleanupTimeout,
	)
	defer cancel()

	var errs []error

	if killFirst {
		if err := group.Kill(); err != nil {
			errs = append(
				errs,
				fmt.Errorf(
					"kill workload cgroup: %w",
					err,
				),
			)
		}
	}

	if err := group.WaitEmpty(cleanupCtx); err != nil {
		errs = append(
			errs,
			fmt.Errorf(
				"wait for workload cgroup to become empty: %w",
				err,
			),
		)
		// Retain allocations and cgroup when live processes cannot be ruled out.
		return errors.Join(errs...)
	}
	for _, allocation := range allocations {
		if allocation != nil {
			if err := allocation.remove(cleanupCtx); err != nil {
				errs = append(errs, fmt.Errorf("remove rootfs %s: %w", allocation.path, err))
			}
		}
	}

	if err := group.Remove(); err != nil {
		errs = append(
			errs,
			fmt.Errorf(
				"remove workload cgroup: %w",
				err,
			),
		)
	}

	return errors.Join(errs...)
}

func (r *Runtime) failPreparing(
	w *workload.Workload,
	group cgroupGroup,
	cause error,
	allocations ...*rootfsAllocation,
) error {
	var errs []error

	if cause != nil {
		errs = append(errs, cause)
	}

	if err := w.Transition(workload.StateCleaning); err != nil {
		errs = append(
			errs,
			fmt.Errorf(
				"transition workload to cleaning: %w",
				err,
			),
		)
	} else {
		r.record(
			audit.EventCleanupStarted,
			w.ID(),
			0,
			"",
		)
		if group != nil {
			if err := r.cleanupGroup(group, true, allocations...); err != nil {
				errs = append(errs, err)
				r.record(audit.EventCleanupFailed, w.ID(), 0, "resource_cleanup")
			}
		}

		if err := w.Transition(workload.StateFailed); err != nil {
			errs = append(
				errs,
				fmt.Errorf(
					"transition workload to failed: %w",
					err,
				),
			)
		} else {
			r.record(
				audit.EventWorkloadFailed,
				w.ID(),
				0,
				"",
			)
		}
	}

	return errors.Join(errs...)
}

func (r *Runtime) record(
	eventType audit.EventType,
	workloadID string,
	pid int,
	reason string,
) {
	if r.audit == nil {
		return
	}

	r.audit.Record(audit.Event{
		Time:       time.Now(),
		Type:       eventType,
		WorkloadID: workloadID,
		PID:        pid,
		Reason:     reason,
	})
}
