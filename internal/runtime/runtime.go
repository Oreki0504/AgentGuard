package runtime

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/audit"
	"github.com/Oreki0504/AgentGuard/internal/cgroupv2"
	"github.com/Oreki0504/AgentGuard/internal/runner"
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
	CgroupRoot     string
	CleanupTimeout time.Duration
	Audit          audit.Sink
}

type Runtime struct {
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
			}
		}

		r.record(
			audit.EventWorkloadTerminating,
			w.ID(),
			0,
			string(reason),
		)

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

	if cleaningErr == nil {
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
	); err != nil {
		failed = true
		errs = append(errs, err)
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

	return &Runtime{
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
			if err := r.cleanupGroup(group, true); err != nil {
				errs = append(errs, err)
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
