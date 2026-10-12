package linux

import (
	"fmt"
	"runtime"
)

// ShellFiles is the initial approved Debian/Ubuntu amd64 tool set. Adding a
// tool requires operator-supplied File mappings, including its dependencies.
func ShellFiles() ([]File, error) {
	if runtime.GOARCH != "amd64" {
		return nil, fmt.Errorf("default shell tool set requires Linux amd64; configure explicit files on other hosts")
	}
	return []File{
		{Source: "/usr/bin/dash", Target: "/bin/sh"},
		{Source: "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", Target: "/lib64/ld-linux-x86-64.so.2"},
		{Source: "/usr/lib/x86_64-linux-gnu/libc.so.6", Target: "/usr/lib/x86_64-linux-gnu/libc.so.6"},
	}, nil
}
