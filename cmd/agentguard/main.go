package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/Oreki0504/AgentGuard/internal/runner"
)

func main() {

	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: agentguard run [--timeout duration] -- <command> [args...]")
		os.Exit(2)
	}

	runFlags := flag.NewFlagSet("run", flag.ContinueOnError)

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
	)
	defer stop()

	result, err := runner.Run(ctx, runner.Request{
		Command: command,
		Args:    args,
		Timeout: *timeout,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "agentguard: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprint(os.Stdout, result.Stdout)
	fmt.Fprint(os.Stderr, result.Stderr)

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
