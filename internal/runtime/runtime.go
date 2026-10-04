package runtime

import (
	"context"
	"fmt"

	"github.com/Oreki0504/AgentGuard/internal/runner"
	"github.com/Oreki0504/AgentGuard/internal/workload"
)

func requestFromSpec(spec workload.Spec) runner.Request {
	return runner.Request{
		Command:    spec.Command,
		Args:       append([]string(nil), spec.Args...),
		WorkingDir: spec.WorkingDir,
		Env:        append([]string(nil), spec.Env...),
		Timeout:    spec.Timeout,
	}
}

func Run(ctx context.Context, w *workload.Workload) (runner.Result, error) {
	if w == nil {
		return runner.Result{}, fmt.Errorf("workload must not be nil")
	}

	if w.State() != workload.StatePreparing {
		return runner.Result{}, fmt.Errorf(
			"workload must be preparing before run: current state %s",
			w.State(),
		)
	}

	if err := w.Transition(workload.StateRunning); err != nil {
		return runner.Result{}, fmt.Errorf(
			"transition workload to running: %w",
			err,
		)
	}

	result, runErr := runner.Run(
		ctx,
		requestFromSpec(w.Spec()),
	)

	if result.TimedOut || result.Canceled {
		if err := w.Transition(workload.StateTerminating); err != nil {
			return runner.Result{}, fmt.Errorf(
				"transition workload to terminating: %w",
				err,
			)
		}
	}

	if err := w.Transition(workload.StateCleaning); err != nil {
		return result, fmt.Errorf(
			"transition workload to cleaning: %w",
			err,
		)
	}

	terminalState := workload.StateFinished

	if runErr != nil || result.TimedOut || result.Canceled {
		terminalState = workload.StateFailed
	}

	if err := w.Transition(terminalState); err != nil {
		return result, fmt.Errorf(
			"transition workload to %s: %w",
			terminalState,
			err,
		)
	}

	if runErr != nil {
		return result, fmt.Errorf("runner execution failed: %w", runErr)
	}

	return result, nil
}
