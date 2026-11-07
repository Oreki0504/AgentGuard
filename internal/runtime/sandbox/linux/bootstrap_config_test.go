package linux

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestBootstrapWireContract(t *testing.T) {
	c := testConfig(t)
	c.Argv = []string{"/bin/sh", "", "-c", "printf ok"}
	c.Env = []string{"A=1", "EMPTY="}
	data, err := encodeBootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("/\x00/bin/sh\x00\x00-c\x00printf ok\x00A=1\x00EMPTY=\x00")
	// Literal independent header for the documented C protocol: version 1,
	// payload length 35, argc 4, envc 2.
	header, err := hex.DecodeString("4147424f4f540001000000230000000400000002")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, append(header, payload...)) {
		t.Fatalf("wrong C contract bytes: %x", data)
	}
}

func TestBootstrapConfigRejectsUnsafeLayout(t *testing.T) {
	tests := map[string]func(*Config){
		"bootstrap file":        func(c *Config) { c.Files = append(c.Files, File{Source: "/usr/bin/dash", Target: bootstrapEntry}) },
		"bootstrap directory":   func(c *Config) { c.Mounts = []BindMount{{Source: "/tmp", Target: "/.agentguard"}} },
		"workspace executable":  func(c *Config) { c.Files[0].Target = "/workspace/sh"; c.Argv[0] = "/workspace/sh" },
		"nested workspace":      func(c *Config) { c.Mounts = []BindMount{{Source: "/tmp", Target: "/workspace/sub"}} },
		"unapproved executable": func(c *Config) { c.Argv[0] = "/bin/missing" },
		"argv count":            func(c *Config) { c.Argv = append(c.Argv, make([]string, bootstrapMaxStrings)...) },
		"env count":             func(c *Config) { c.Env = make([]string, bootstrapMaxStrings+1) },
		"path length":           func(c *Config) { c.WorkingDir = "/" + strings.Repeat("x", 4095) },
		"payload length":        func(c *Config) { c.Argv = append(c.Argv, strings.Repeat("x", MaxConfigSize)) },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			change(&c)
			if _, err := encodeBootstrapConfig(c); err == nil {
				t.Fatal("unsafe bootstrap input accepted")
			}
			if c.Validate() == nil {
				t.Fatal("unsafe bootstrap input passed outer launch validation")
			}
		})
	}
}

func TestBootstrapConfigMaximumFrame(t *testing.T) {
	c := testConfig(t)
	c.Argv = append(c.Argv, "")
	base, err := encodeBootstrapConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Argv[1] = strings.Repeat("x", MaxConfigSize-len(base))
	data, err := encodeBootstrapConfig(c)
	if err != nil || len(data) != MaxConfigSize {
		t.Fatalf("maximum frame: size=%d err=%v", len(data), err)
	}
	c.Argv[1] += "x"
	if _, err := encodeBootstrapConfig(c); err == nil {
		t.Fatal("oversized frame accepted")
	}
}

func TestBootstrapConfigDescriptorIsReadOnlyAndUnlinked(t *testing.T) {
	t.Setenv("AGENTGUARD_SECRET", "must-not-inherit")
	c := testConfig(t)
	c.Env = []string{"EXPLICIT=only"}
	dir := t.TempDir()
	file, err := newBootstrapConfig(c, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_GETFL, 0)
	if errno != 0 || flags&syscall.O_ACCMODE != syscall.O_RDONLY {
		t.Fatalf("configuration is not read-only: flags=%x errno=%v", flags, errno)
	}
	info, err := file.Stat()
	if err != nil || info.Sys().(*syscall.Stat_t).Nlink != 0 {
		t.Fatalf("configuration is not anonymous: %v", err)
	}
	if _, err := file.Write([]byte("tamper")); err == nil {
		t.Fatal("configuration allowed a write")
	}
	data, err := io.ReadAll(file)
	if err != nil || !bytes.Contains(data, []byte("EXPLICIT=only")) ||
		bytes.Contains(data, []byte("must-not-inherit")) {
		t.Fatalf("wrong explicit configuration: err=%v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("configuration file leaked: %v", err)
	}
	fd := file.Fd()
	if err := closeVerified(file); err != nil {
		t.Fatal(err)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0); errno != syscall.EBADF {
		t.Fatalf("configuration FD leaked: %v", errno)
	}
}

func TestBootstrapPreparationRejectsBeforeMount(t *testing.T) {
	c := testConfig(t)
	if err := prepareBootstrapRootfs(c, nil, nil); err == nil {
		t.Fatal("missing bootstrap accepted")
	}
	source, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	c.Files = append(c.Files, File{Source: "/dev/null", Target: bootstrapEntry})
	if err := prepareBootstrapRootfs(c, nil, source); err == nil {
		t.Fatal("bootstrap path collision accepted")
	}
	if _, err := os.Stat(c.Rootfs); !os.IsNotExist(err) {
		t.Fatalf("invalid input reached filesystem setup: %v", err)
	}
}

func TestCopyApprovedFileRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	source, err := os.Open("/usr/bin/dash")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := copyApprovedFile(source, target); err == nil {
		t.Fatal("existing file overwritten")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "existing" {
		t.Fatal("existing file changed")
	}
}
