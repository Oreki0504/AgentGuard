package runner

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

func TestRunOutputLimit(t *testing.T) {
	result, err := Run(context.Background(), Request{
		Command: os.Args[0],
		Args: []string{
			"-test.run=^TestRunnerLargeOutputHelper$",
		},
		Env: []string{
			"AGENTGUARD_TEST_OUTPUT_HELPER=1",
		},
		Timeout: 5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Fatalf("unexpected exit code: %d", result.ExitCode)
	}

	if len(result.Stdout) != maxCapturedOutputBytes {
		t.Fatalf(
			"stdout size = %d, want %d",
			len(result.Stdout),
			maxCapturedOutputBytes,
		)
	}

	if len(result.Stderr) != maxCapturedOutputBytes {
		t.Fatalf(
			"stderr size = %d, want %d",
			len(result.Stderr),
			maxCapturedOutputBytes,
		)
	}

	if !result.StdoutTruncated || !result.StderrTruncated {
		t.Fatalf(
			"expected both streams to be truncated: %+v",
			result,
		)
	}
}

func TestRunnerLargeOutputHelper(t *testing.T) {
	if os.Getenv("AGENTGUARD_TEST_OUTPUT_HELPER") != "1" {
		return
	}

	chunk := bytes.Repeat([]byte("x"), 32*1024)

	for i := 0; i < 40; i++ {
		if _, err := os.Stdout.Write(chunk); err != nil {
			os.Exit(2)
		}
		if _, err := os.Stderr.Write(chunk); err != nil {
			os.Exit(3)
		}
	}

	os.Exit(0)
}
