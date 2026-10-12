package main

import (
	"os"

	"github.com/Oreki0504/AgentGuard/internal/runtime/sandbox/linux"
)

func main() { os.Exit(linux.Launch(os.Args[1:])) }
