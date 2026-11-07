package main

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/Oreki0504/AgentGuard/internal/runner"
)

func TestReportResult(t *testing.T) {
	for _, test := range []struct {
		name   string
		result runner.Result
		err    error
		code   int
		out    string
		errout string
	}{
		{"startup-diagnostic", runner.Result{Stdout: "partial output\n", Stderr: "agentguard-bootstrap: guest exec\n", ExitCode: -1},
			errors.New("sandbox startup failed"), 1, "partial output\n", "agentguard-bootstrap: guest exec\nagentguard: sandbox startup failed\n"},
		{"truncated-startup-diagnostic", runner.Result{Stdout: "out", Stderr: "diagnostic\n", StdoutTruncated: true, StderrTruncated: true, ExitCode: -1},
			errors.New("startup failed"), 1, "out", "diagnostic\nagentguard: warning: stdout was truncated\nagentguard: warning: stderr was truncated\nagentguard: startup failed\n"},
		{"success", runner.Result{Stdout: "ok\n"}, nil, 0, "ok\n", ""},
		{"guest-failure", runner.Result{ExitCode: 42, Stderr: "guest error\n"}, nil, 42, "", "guest error\n"},
		{"timeout", runner.Result{TimedOut: true, Duration: time.Second}, nil, 124, "", "agentguard: command timed out after 1s\n"},
		{"canceled", runner.Result{Canceled: true}, nil, 130, "", "agentguard: canceled\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, errout bytes.Buffer
			code := reportResult(test.result, test.err, &out, &errout)
			if code != test.code || out.String() != test.out || errout.String() != test.errout {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errout.String())
			}
		})
	}
}
