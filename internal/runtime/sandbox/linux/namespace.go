package linux

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
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

// Check the actual attached domain before creating UserNS or preparing rootfs.
// Namespace-local labels alone can conceal an outer stacked profile.
func checkLauncherProfile(readFile func(string) ([]byte, error)) error {
	label, err := readFile("/proc/self/attr/apparmor/current")
	if err != nil || string(label) != "agentguard-launcher (enforce)\n" {
		return &Failure{Stage: "privilege", Reason: "unexpected launcher AppArmor label"}
	}
	for _, name := range []string{".stacked", ".ns_stacked"} {
		data, err := readFile("/sys/kernel/security/apparmor/" + name)
		if err != nil || strings.TrimSpace(string(data)) != "no" {
			return &Failure{Stage: "privilege", Reason: "unexpected launcher AppArmor stacking"}
		}
	}
	return nil
}

// Launch is the only executable entry point. The namespace init has an
// independent status pipe; it never inherits the outer Runtime status FD.
func Launch(args []string) int {
	configFile := os.NewFile(3, "config")
	status := os.NewFile(4, "status")
	defer status.Close()
	defer configFile.Close()
	if err := checkLauncherProfile(os.ReadFile); err != nil {
		return reportFailure(status, "privilege", err.Error())
	}
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
	bootstrap := os.NewFile(uintptr(5+len(sources)), "bootstrap")
	defer bootstrap.Close()
	// Bind the supplied handle to the fixed installed source in both outer
	// and init processes. No caller-selected image may use the Cx entry.
	installed, err := openSource(BootstrapPath, false)
	if err != nil {
		return reportFailure(status, "config", "cannot inspect installed bootstrap")
	}
	providedInfo, providedErr := bootstrap.Stat()
	installedInfo, installedErr := installed.Stat()
	installed.Close()
	if providedErr != nil || installedErr != nil || !os.SameFile(providedInfo, installedInfo) {
		return reportFailure(status, "config", "bootstrap source identity mismatch")
	}
	if len(args) == 1 && args[0] == "--init" {
		if err := closeVerified(configFile); err != nil {
			return reportFailure(status, "config", "cannot close host configuration")
		}
		if os.Getpid() != 1 {
			return reportFailure(status, "namespace", "init must be namespace PID 1")
		}
		return runInit(c, sources, bootstrap, status)
	}
	if len(args) != 0 {
		return reportFailure(status, "config", "unexpected launcher argument")
	}
	if err := ValidateTrustedExecutable(BootstrapPath); err != nil {
		return reportFailure(status, "config", "untrusted installed bootstrap")
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
	cmd.ExtraFiles = append(append([]*os.File{configFile, childWrite}, sources...), bootstrap)
	cmd.SysProcAttr = namespaceAttributes()
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		return reportFailure(status, "namespace", "cannot start namespace init")
	}
	childWrite.Close()
	configFile.Close()
	bootstrap.Close()
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
