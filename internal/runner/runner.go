package runner

import (
	"bytes"
	"errors"
	"os/exec"
)

type Request struct {
	Command    string
	Args       []string
	WorkingDir string
}

type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

func Run(req Request) (Result, error) {
	cmd := exec.Command(req.Command, req.Args...)

	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	result := Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: -1,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
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
