package main

import (
	"fmt"
	"os"

	"github.com/Oreki0504/AgentGuard/internal/runner"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: agentguard run -- <command> [args...]")
		os.Exit(1)
	}

	if os.Args[1] != "run" || os.Args[2] != "--" {
		fmt.Fprintln(os.Stderr, "usage: agentguard run -- <command> [args...]")
		os.Exit(1)
	}

	command := os.Args[3]
	args := os.Args[4:]

	result, err := runner.Run(runner.Request{
		Command: command,
		Args:    args,
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "agentguard: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprint(os.Stdout, result.Stdout)
	fmt.Fprint(os.Stderr, result.Stderr)

	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}
}
