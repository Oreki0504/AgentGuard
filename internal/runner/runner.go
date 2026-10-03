package runner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

type Request struct {
	Command    string
	Args       []string
	WorkingDir string
	Env        []string
	Timeout    time.Duration
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	TimedOut bool
	Canceled bool
}

func Run(ctx context.Context, req Request) (Result, error) {
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

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	cmd.Env = append([]string{}, req.Env...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()

	err := cmd.Start()

	if err != nil {
		return Result{
			ExitCode: -1,
			Duration: time.Since(start),
		}, err
	}

	waitCh := make(chan error, 1)

	go func() {
		waitCh <- cmd.Wait()
	}()
	select {
	case err = <-waitCh:

	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)

		err = <-waitCh
	}

	duration := time.Since(start)

	result := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: -1,
		Duration: duration,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
		return result, nil
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		result.Canceled = true
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
