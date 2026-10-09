package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func must(operation string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
		os.Exit(1)
	}
}
func copyHostFile(src, dst string, mode os.FileMode) {
	data, err := os.ReadFile(src)
	must("read host file "+src, err)

	must("copy file to sandbox "+dst,
		os.WriteFile(dst, data, mode))
}
func prepareRootfs(newRoot string) {
	// Create and mount the new root filesystem.
	must("create root directory",
		os.MkdirAll(newRoot, 0o700))

	must("mount new rootfs", syscall.Mount(
		"tmpfs",
		newRoot,
		"tmpfs",
		syscall.MS_NOSUID|syscall.MS_NODEV,
		"size=32m,mode=0700",
	))

	// Prepare executable and library directories.
	must("create bin directory",
		os.MkdirAll(newRoot+"/bin", 0o755))

	must("create loader directory",
		os.MkdirAll(newRoot+"/lib64", 0o755))

	must("create shared library directory",
		os.MkdirAll(
			newRoot+"/usr/lib/x86_64-linux-gnu",
			0o755,
		))

	// Copy the minimum dynamic shell dependencies.
	copyHostFile(
		"/usr/bin/dash",
		newRoot+"/bin/sh",
		0o755,
	)

	copyHostFile(
		"/lib64/ld-linux-x86-64.so.2",
		newRoot+"/lib64/ld-linux-x86-64.so.2",
		0o755,
	)

	copyHostFile(
		"/usr/lib/x86_64-linux-gnu/libc.so.6",
		newRoot+"/usr/lib/x86_64-linux-gnu/libc.so.6",
		0o755,
	)

	// Prepare read-only workspace.
	const hostWorkspace = "/tmp/agentguard-probe-workspace"

	workspace := newRoot + "/workspace"

	must("create workspace mountpoint",
		os.Mkdir(workspace, 0o700))

	must("bind mount workspace", syscall.Mount(
		hostWorkspace,
		workspace,
		"",
		syscall.MS_BIND,
		"",
	))

	must("remount workspace read-only", syscall.Mount(
		"",
		workspace,
		"",
		syscall.MS_BIND|
			syscall.MS_REMOUNT|
			syscall.MS_RDONLY|
			syscall.MS_NOSUID|
			syscall.MS_NODEV|
			syscall.MS_NOEXEC,
		"",
	))
}
func switchRoot(newRoot string) error {
	oldRoot := newRoot + "/.oldroot"

	if err := os.Mkdir(oldRoot, 0o700); err != nil {
		return fmt.Errorf("create old root mountpoint: %w", err)
	}

	if err := syscall.PivotRoot(newRoot, oldRoot); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir to new root: %w", err)
	}

	if err := syscall.Unmount("/.oldroot", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}

	if err := os.Remove("/.oldroot"); err != nil {
		return fmt.Errorf("remove old root mountpoint: %w", err)
	}

	return nil
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--child":
			if len(os.Args) != 3 {
				fmt.Fprintln(os.Stderr, "missing rootfs directory")
				os.Exit(2)
			}

			runChild(os.Args[2])
			return
		}
	}
	exe, err := os.Executable()
	must("resolve executable", err)

	// Allocate a unique host-side mountpoint.
	rootDir, err := os.MkdirTemp("/tmp", "agentguard-rootfs-")
	must("create host rootfs directory", err)

	fmt.Println("Host rootfs directory:", rootDir)

	// Pass the directory to the sandbox child.
	cmd := exec.Command(exe, "--child", rootDir)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER |
			syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			},
		},

		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			},
		},

		GidMappingsEnableSetgroups: false,
	}

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()

	// This runs even if the child exits with an error.
	cleanupErr := os.Remove(rootDir)

	if runErr != nil {
		fmt.Fprintln(os.Stderr, "sandbox child:", runErr)
	}

	if cleanupErr != nil {
		fmt.Fprintln(os.Stderr, "cleanup host rootfs directory:", cleanupErr)
	}

	if runErr != nil || cleanupErr != nil {
		os.Exit(1)
	}

}

func runChild(newRoot string) {
	//1. Prevent mount propagation to the host.
	must("make mounts private", syscall.Mount(
		"", "/", "",
		syscall.MS_REC|syscall.MS_PRIVATE,
		"",
	))
	// 2. Prepare rootfs.
	prepareRootfs(newRoot)
	if os.Getenv("AGENTGUARD_PROBE_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "intentional setup failure")
		os.Exit(42)
	}
	//3. Reverse a Location for the old root.

	fmt.Println("Before pivot_root")
	fmt.Println("Host /etc/passwd visible?")

	_, statErr := os.Stat("/etc/passwd")
	fmt.Println(statErr == nil)

	must("switch root", switchRoot(newRoot))
	must("write sandbox file", os.WriteFile(
		"/inside.txt",
		[]byte("Hello from isolated rootfs!\n"),
		0o600,
	))

	//6. Vertify the isolated filesystem.

	content, err := os.ReadFile("/workspace/host.txt")
	must("read workspace file", err)

	fmt.Printf("Workspace content: %s", content)

	err = os.WriteFile(
		"/workspace/should-fail.txt",
		[]byte("test"),
		0o600,
	)

	if err == nil {
		fmt.Fprintln(os.Stderr, "ERROR: read-only mount allowed writing")
		os.Exit(1)
	}

	fmt.Println("Expected write failure:", err)
	fmt.Println("Executing workload inside sandbox...")

	shellScript := `
set -eu

printf 'Hello from dynamic /bin/sh!\n'

printf 'Current directory: '
pwd

IFS= read -r line < /workspace/host.txt
printf 'Workspace content: %s\n' "$line"

IFS= read -r inside < /inside.txt
printf 'Sandbox file: %s\n' "$inside"

if [ -e /etc/passwd ]; then
    printf 'ERROR: host /etc/passwd is visible\n'
    exit 1
fi

printf 'Host /etc/passwd unavailable\n'
`

	fmt.Println("Executing dynamic shell inside sandbox...")

	must("exec dynamic shell", syscall.Exec(
		"/bin/sh",
		[]string{"/bin/sh", "-c", shellScript},
		[]string{"PATH=/bin"},
	))
}
