package linux

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBootstrapNullStdio(t *testing.T) {
	for _, mode := range []string{"null-read", "null-readwrite", "null-nonblock", "pipe", "regular", "wrong-device", "wrong-stream-device", "symlink-target", "regular-target", "closed", "cloexec", "wrong-access"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestBootstrapNullStdioHelper$")
			cmd.Env = []string{"AGENTGUARD_NULL_STDIO_HELPER=" + mode, "AGENTGUARD_NULL_STDIO_DIR=" + t.TempDir()}
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("stdio case %s: %v\n%s", mode, err, output)
			}
		})
	}
}

func TestBootstrapNullStdioHelper(t *testing.T) {
	mode := os.Getenv("AGENTGUARD_NULL_STDIO_HELPER")
	if mode == "" {
		return
	}
	null := "/dev/null"
	openFlags := syscall.O_RDONLY
	if mode == "null-readwrite" {
		openFlags = syscall.O_RDWR
	}
	if mode == "wrong-access" {
		openFlags = syscall.O_WRONLY
	}
	if mode == "null-nonblock" {
		openFlags |= syscall.O_NONBLOCK
	}
	sourcePath := "/dev/null"
	if mode == "wrong-stream-device" {
		sourcePath = "/dev/zero"
	}
	source, err := syscall.Open(sourcePath, openFlags, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(source)
	if mode == "pipe" {
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer read.Close()
		defer write.Close()
		source = int(read.Fd())
	}
	if mode == "regular" || mode == "regular-target" {
		file, err := os.Create(filepath.Join(os.Getenv("AGENTGUARD_NULL_STDIO_DIR"), "regular"))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if mode == "regular" {
			source = int(file.Fd())
		} else {
			null = file.Name()
		}
	}
	if mode == "symlink-target" {
		null = filepath.Join(os.Getenv("AGENTGUARD_NULL_STDIO_DIR"), "null")
		if err := os.Symlink("/dev/null", null); err != nil {
			t.Fatal(err)
		}
	}
	if mode == "wrong-device" {
		null = "/dev/zero"
	}
	if err := syscall.Dup3(source, 0, 0); err != nil {
		t.Fatal(err)
	}
	if mode == "closed" {
		syscall.Close(0)
	}
	if mode == "cloexec" {
		syscall.CloseOnExec(0)
	}
	var outputBefore, outputAfter syscall.Stat_t
	if err := syscall.Fstat(1, &outputBefore); err != nil {
		t.Fatal(err)
	}
	err = rebindBootstrapNullStdio(null)
	wantError := mode == "wrong-device" || mode == "wrong-stream-device" || strings.HasSuffix(mode, "-target") ||
		mode == "closed" || mode == "cloexec" || mode == "wrong-access"
	if wantError {
		if err == nil {
			t.Fatal("unsafe stdio input accepted")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Fstat(1, &outputAfter); err != nil ||
		outputBefore.Dev != outputAfter.Dev || outputBefore.Ino != outputAfter.Ino {
		t.Fatal("stdout pipe changed")
	}
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_GETFL, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	// Changing the original open description distinguishes reopen from dup:
	// null must have a new description, while regular/pipe streams keep theirs.
	_, _, errno = syscall.Syscall(syscall.SYS_FCNTL, uintptr(source), syscall.F_SETFL, flags^syscall.O_NONBLOCK)
	if errno != 0 {
		t.Fatal(errno)
	}
	after, _, errno := syscall.Syscall(syscall.SYS_FCNTL, 0, syscall.F_GETFL, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if strings.HasPrefix(mode, "null-") {
		if int(after)&(syscall.O_NONBLOCK|syscall.O_ACCMODE) != openFlags {
			t.Fatal("null stream was duplicated or its access mode changed")
		}
	} else if after&syscall.O_NONBLOCK == 0 {
		t.Fatal("pipe/regular stream description was replaced")
	}
}
