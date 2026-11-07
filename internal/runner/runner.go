package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type LinuxOptions struct {
	UseCgroupFD bool
	CgroupFD    int
}

type Hooks struct {
	// Run exclusively owns reaping its direct child; hooks must not call wait
	// for this PID. With UseCgroupFD, OnTerminating owns descendant termination.
	OnStarted     func(pid int) error
	OnReady       func(pid int) error
	OnTerminating func(reason TerminationReason) error
}

// Startup.Wait must honor its context. It receives status from a trusted
// launcher channel, never from workload stdout. It runs before OnReady.
type Startup struct {
	Timeout time.Duration
	Wait    func(context.Context) error
}

type Request struct {
	Command    string
	Args       []string
	WorkingDir string
	Env        []string
	Timeout    time.Duration
	Stdin      io.Reader
	ExtraFiles []*os.File
	Startup    *Startup

	Linux LinuxOptions
	Hooks Hooks
}

type Result struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	ExitCode        int
	Duration        time.Duration
	TimedOut        bool
	Canceled        bool
}

type TerminationReason string

const (
	TerminationTimeout  TerminationReason = "timeout"
	TerminationCanceled TerminationReason = "canceled"
	TerminationStartup  TerminationReason = "startup_failed"
)

func Run(ctx context.Context, req Request) (Result, error) {
	if req.Startup != nil && (req.Startup.Timeout <= 0 || req.Startup.Wait == nil) {
		return Result{ExitCode: -1}, fmt.Errorf("invalid startup contract")
	}
	if req.Timeout > 0 {
		var cancel context.CancelFunc

		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	if err := ctx.Err(); err != nil {
		result := Result{
			ExitCode: -1,
		}

		if errors.Is(err, context.DeadlineExceeded) {
			result.TimedOut = true
		}

		if errors.Is(err, context.Canceled) {
			result.Canceled = true
		}

		return result, nil
	}

	cmd := exec.Command(req.Command, req.Args...)

	cmd.WaitDelay = 500 * time.Millisecond

	sysProcAttr := &syscall.SysProcAttr{
		Setpgid: true,
	}

	if req.Linux.UseCgroupFD {
		sysProcAttr.UseCgroupFD = true
		sysProcAttr.CgroupFD = req.Linux.CgroupFD
	}

	cmd.SysProcAttr = sysProcAttr

	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	cmd.Env = append([]string{}, req.Env...)
	cmd.ExtraFiles = req.ExtraFiles

	stdout := limitedBuffer{limit: maxCapturedOutputBytes}
	stderr := limitedBuffer{limit: maxCapturedOutputBytes}

	streams := &commandIO{}
	defer streams.close()
	var err error
	if cmd.Stdin, err = streams.input(req.Stdin); err != nil {
		return Result{ExitCode: -1}, err
	}
	if cmd.Stdout, err = streams.output(&stdout); err != nil {
		return Result{ExitCode: -1}, err
	}
	if cmd.Stderr, err = streams.output(&stderr); err != nil {
		return Result{ExitCode: -1}, err
	}

	start := time.Now()

	err = cmd.Start()

	if err != nil {
		return Result{
			ExitCode: -1,
			Duration: time.Since(start),
		}, err
	}
	waitCh := streams.watch(cmd)
	// Completion above observes exit and drains streams without reaping. Only
	// this goroutine calls Wait, after it has finished sending group signals.
	reap := func(done completion) error {
		err := cmd.Wait()
		if done.exitErr != nil {
			return done.exitErr
		}
		if err != nil {
			return err
		}
		return done.ioErr
	}

	if req.Hooks.OnStarted != nil {
		if err := req.Hooks.OnStarted(cmd.Process.Pid); err != nil {
			killCommand(cmd, req.Linux.UseCgroupFD)

			// The direct child must always be reaped.
			_ = reap(<-waitCh)

			return Result{
				Stdout:          stdout.String(),
				Stderr:          stderr.String(),
				StdoutTruncated: stdout.truncated,
				StderrTruncated: stderr.truncated,
				ExitCode:        -1,
				Duration:        time.Since(start),
			}, fmt.Errorf("runner on-start hook failed: %w", err)
		}
	}

	if req.Startup != nil {
		startupCtx, cancel := context.WithTimeout(ctx, req.Startup.Timeout)
		readyErr := req.Startup.Wait(startupCtx)
		if startupCtx.Err() != nil {
			readyErr = startupCtx.Err()
		}
		cancel()
		if readyErr == nil && req.Hooks.OnReady != nil {
			readyErr = req.Hooks.OnReady(cmd.Process.Pid)
		}
		if readyErr != nil {
			var hookErr error
			reason := TerminationStartup
			if errors.Is(ctx.Err(), context.Canceled) {
				reason = TerminationCanceled
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				reason = TerminationTimeout
			}
			if req.Hooks.OnTerminating != nil {
				hookErr = req.Hooks.OnTerminating(reason)
			}
			killCommand(cmd, req.Linux.UseCgroupFD)
			_ = reap(<-waitCh)
			return Result{
				Stdout:          stdout.String(),
				Stderr:          stderr.String(),
				StdoutTruncated: stdout.truncated,
				StderrTruncated: stderr.truncated,
				ExitCode:        -1,
				Duration:        time.Since(start),
				TimedOut:        errors.Is(readyErr, context.DeadlineExceeded),
				Canceled:        errors.Is(ctx.Err(), context.Canceled),
			}, errors.Join(fmt.Errorf("sandbox startup: %w", readyErr), hookErr)
		}
	}

	var terminatingErr error
	var done completion

	select {
	case done = <-waitCh:
		// Process exited on its own.

	case <-ctx.Done():
		var reason TerminationReason

		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			reason = TerminationTimeout
		} else {
			reason = TerminationCanceled
		}

		if req.Hooks.OnTerminating != nil {
			terminatingErr = req.Hooks.OnTerminating(reason)
		}

		killCommand(cmd, req.Linux.UseCgroupFD)

		done = <-waitCh
	}
	err = reap(done)

	duration := time.Since(start)

	result := Result{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
		ExitCode:        -1,
		Duration:        duration,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true

		if terminatingErr != nil {
			return result, fmt.Errorf(
				"runner on-terminating hook failed: %w",
				terminatingErr,
			)
		}

		return result, nil
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		result.Canceled = true

		if terminatingErr != nil {
			return result, fmt.Errorf(
				"runner on-terminating hook failed: %w",
				terminatingErr,
			)
		}

		return result, nil
	}

	if err != nil {
		var exitErr *exec.ExitError

		if errors.As(err, &exitErr) {
			return result, nil
		}

		return result, err
	}

	return result, nil
}
