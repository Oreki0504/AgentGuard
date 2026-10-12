package linux

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{Version: Version, WorkloadID: "test", Argv: []string{"/bin/sh"}, WorkingDir: "/", Rootfs: filepath.Join(t.TempDir(), "root"), StartupTimeout: time.Second,
		Files: []File{{Source: "/usr/bin/dash", Target: "/bin/sh"}}}
}

func TestConfigRejectsUnsafeInputs(t *testing.T) {
	tests := map[string]func(*Config){
		"relative executable": func(c *Config) { c.Argv[0] = "sh" },
		"traversal":           func(c *Config) { c.Mounts = []BindMount{{Source: "/tmp", Target: "/workspace/../proc"}} },
		"reserved proc":       func(c *Config) { c.Mounts = []BindMount{{Source: "/tmp", Target: "/proc/x"}} },
		"root exposure":       func(c *Config) { c.Mounts = []BindMount{{Source: "/", Target: "/workspace"}} },
		"nested targets": func(c *Config) {
			c.Mounts = []BindMount{{Source: "/tmp", Target: "/workspace"}, {Source: "/tmp", Target: "/workspace/x"}}
		},
		"shadow tool":            func(c *Config) { c.Mounts = []BindMount{{Source: "/tmp", Target: "/bin"}} },
		"NUL argv":               func(c *Config) { c.Argv = append(c.Argv, "x\x00y") },
		"duplicate env":          func(c *Config) { c.Env = []string{"X=1", "X=2"} },
		"invalid env":            func(c *Config) { c.Env = []string{"secret"} },
		"unbounded startup":      func(c *Config) { c.StartupTimeout = MaxStartupTimeout + 1 },
		"root working traversal": func(c *Config) { c.WorkingDir = "/../" },
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			c := testConfig(t)
			change(&c)
			if c.Validate() == nil {
				t.Fatal("unsafe config accepted")
			}
		})
	}
}

func TestMessageRejectsMalformedFrames(t *testing.T) {
	valid := func(body string) []byte {
		var b bytes.Buffer
		binary.Write(&b, binary.BigEndian, uint32(len(body)))
		b.WriteString(body)
		return b.Bytes()
	}
	for _, data := range [][]byte{nil, {0, 0, 0}, {255, 255, 255, 255}, valid(`{"version":1,"type":"READY","extra":1}`), valid(`{"version":2,"type":"READY"}`), valid(`{"version":1,"type":"EXIT"}`), valid(`{"version":1,"type":"READY"} {}`)} {
		if _, err := ReadMessage(bytes.NewReader(data)); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
	var b bytes.Buffer
	code := 42
	for _, m := range []Message{{Version: Version, Type: "READY"}, {Version: Version, Type: "EXIT", ExitCode: &code}, {Version: Version, Type: "ERROR", Stage: "exec", Reason: "failed"}} {
		b.Reset()
		if err := WriteMessage(&b, m); err != nil {
			t.Fatal(err)
		}
		got, err := ReadMessage(&b)
		if err != nil || got.Type != m.Type {
			t.Fatalf("roundtrip: %+v %v", got, err)
		}
	}
}

func TestSessionFailsPromptlyWithoutReady(t *testing.T) {
	for _, mode := range []string{"EOF", "ERROR", "EXIT", "garbage", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			s := &Session{read: r}
			switch mode {
			case "EOF":
				w.Close()
			case "ERROR":
				WriteMessage(w, Message{Version: Version, Type: "ERROR", Stage: "exec", Reason: "failed"})
			case "EXIT":
				code := 0
				WriteMessage(w, Message{Version: Version, Type: "EXIT", ExitCode: &code})
			case "garbage":
				w.Write([]byte("wrong"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			start := time.Now()
			if err := s.WaitReady(ctx); err == nil {
				t.Fatal("missing READY accepted")
			}
			if mode != "timeout" && time.Since(start) > 40*time.Millisecond {
				t.Fatal("explicit startup failure waited for deadline")
			}
		})
	}
}

func TestSourceSymlinksAndRename(t *testing.T) {
	base := t.TempDir()
	original := filepath.Join(base, "original")
	os.Mkdir(original, 0700)
	link := filepath.Join(base, "link")
	os.Symlink(original, link)
	if f, err := openSource(link, true); err == nil {
		f.Close()
		t.Fatal("directory symlink accepted")
	}
	file := filepath.Join(original, "file")
	os.WriteFile(file, []byte("original"), 0600)
	if f, err := openSource(filepath.Join(link, "file"), false); err == nil {
		f.Close()
		t.Fatal("ancestor symlink accepted")
	}
	f, err := openSource(file, false)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	os.Rename(file, file+"-old")
	os.WriteFile(file, []byte("replacement"), 0600)
	var b bytes.Buffer
	b.ReadFrom(f)
	if b.String() != "original" {
		t.Fatal("source pin followed replacement")
	}
}

func TestPrepareDoesNotInheritEnvironment(t *testing.T) {
	t.Setenv("AGENTGUARD_SECRET", "do-not-copy")
	c := testConfig(t)
	c.Env = []string{"EXPLICIT=value"}
	s, err := Prepare(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var got Config
	if err := readFrame(s.config, &got, MaxConfigSize); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Env, ",") != "EXPLICIT=value" {
		t.Fatalf("unexpected guest env: %v", got.Env)
	}
}
