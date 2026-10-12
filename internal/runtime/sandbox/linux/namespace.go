package linux

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
)

func namespaceAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
}

func reportFailure(status *os.File, stage, reason string) int {
	_ = WriteMessage(status, Message{Version: Version, Type: "ERROR", Stage: stage, Reason: reason})
	return 125
}

// Launch is the only executable entry point. The namespace init has an
// independent status pipe; it never inherits the outer Runtime status FD.
func Launch(args []string) int {
	configFile := os.NewFile(3, "config")
	status := os.NewFile(4, "status")
	defer status.Close()
	// Go preserves inherited non-CLOEXEC descriptors unless told otherwise.
	// Mark every non-stdio descriptor before either re-exec or guest exec;
	// ExtraFiles below is the only allowlist that can clear CLOEXEC again.
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return reportFailure(status, "config", "cannot inspect inherited descriptors")
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err == nil && fd >= 3 {
			syscall.CloseOnExec(fd)
		}
	}
	syscall.CloseOnExec(3)
	syscall.CloseOnExec(4)
	var c Config
	if err := readFrame(configFile, &c, MaxConfigSize); err != nil {
		return reportFailure(status, "config", "invalid configuration frame")
	}
	if err := c.Validate(); err != nil {
		return reportFailure(status, "config", "invalid launch configuration")
	}
	sources := make([]*os.File, len(c.Files)+len(c.Mounts))
	for i := range sources {
		sources[i] = os.NewFile(uintptr(5+i), "source")
		syscall.CloseOnExec(5 + i)
		defer sources[i].Close()
	}
	if len(args) == 1 && args[0] == "--init" {
		configFile.Close()
		if os.Getpid() != 1 {
			return reportFailure(status, "namespace", "init must be namespace PID 1")
		}
		return runInit(c, sources, status)
	}
	if len(args) != 0 {
		return reportFailure(status, "config", "unexpected launcher argument")
	}
	if _, err := configFile.Seek(0, io.SeekStart); err != nil {
		return reportFailure(status, "config", "cannot rewind config")
	}
	exe, err := os.Executable()
	if err != nil {
		return reportFailure(status, "namespace", "cannot resolve launcher")
	}
	childRead, childWrite, err := os.Pipe()
	if err != nil {
		return reportFailure(status, "namespace", "cannot create init channel")
	}
	defer childRead.Close()
	defer childWrite.Close()
	cmd := exec.Command(exe, "--init")
	cmd.Env = []string{}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = append([]*os.File{configFile, childWrite}, sources...)
	cmd.SysProcAttr = namespaceAttributes()
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return reportFailure(status, "namespace", "cannot start namespace init")
	}
	childWrite.Close()
	configFile.Close()
	for _, f := range sources {
		f.Close()
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case s := <-signals:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	// Runner imposes the startup deadline and kills the entire cgroup on any
	// failure. Closing this pipe on child death yields an immediate failure.
	ready, err := ReadMessage(childRead)
	if err != nil || (ready.Type != "READY" && ready.Type != "ERROR") {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return reportFailure(status, "protocol", "init exited before READY or sent invalid status")
	}
	if err := WriteMessage(status, ready); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 125
	}
	if ready.Type == "ERROR" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return 125
	}
	result, readErr := ReadMessage(childRead)
	if readErr != nil || (result.Type != "EXIT" && result.Type != "ERROR") {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return reportFailure(status, "init", "init exited without a valid result")
	}
	waitErr := cmd.Wait()
	if result.Type == "ERROR" {
		_ = WriteMessage(status, result)
		return 125
	}
	if waitErr != nil {
		return reportFailure(status, "init", "init did not terminate normally")
	}
	if err := WriteMessage(status, result); err != nil {
		return 125
	}
	return 0 // The actual command's status is carried by EXIT, never guessed.
}

func sourcePath(index int) string { return fmt.Sprintf("/proc/self/fd/%d", 5+index) }
