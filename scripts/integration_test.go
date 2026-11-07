package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegrationChecksArtifactsBeforeCgroupSetup(t *testing.T) {
	script, err := os.ReadFile("test-integration.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stale-launcher", "stale-bootstrap", "matching"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, content string, perm os.FileMode) string {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), perm); err != nil {
					t.Fatal(err)
				}
				return path
			}
			entry := write("scripts/test-integration.sh", string(script), 0600)
			write("bin/agentguard-launcher", "launcher", 0600)
			write("bin/agentguard-bootstrap", "bootstrap", 0600)
			launcher := write("installed-launcher", "launcher", 0600)
			bootstrap := write("installed-bootstrap", "bootstrap", 0600)
			if mode == "stale-launcher" {
				write("installed-launcher", "old", 0600)
			}
			if mode == "stale-bootstrap" {
				write("installed-bootstrap", "old", 0600)
			}
			// Only redirect the fixed installed Bootstrap in this disposable
			// command harness; production gains no configurable Bootstrap path.
			write("tools/cmp", `#!/bin/sh
printf 'cmp %s\n' "$2" >> "$TEST_EVENTS"
if [ "$2" = /usr/local/libexec/agentguard-bootstrap ]; then
  exec /usr/bin/cmp "$1" "$TEST_BOOTSTRAP"
fi
exec /usr/bin/cmp "$@"
`, 0700)
			for _, tool := range []string{"sed", "mkdir", "go"} {
				write("tools/"+tool, "#!/bin/sh\nprintf '"+tool+"\\n' >> \"$TEST_EVENTS\"\nexit 77\n", 0700)
			}
			events := filepath.Join(root, "events")
			cmd := exec.Command("/bin/sh", entry, "-run", "^SelectedCase$")
			cmd.Env = []string{"PATH=" + filepath.Join(root, "tools") + ":/usr/bin:/bin",
				"AGENTGUARD_LAUNCHER=" + launcher, "TEST_BOOTSTRAP=" + bootstrap, "TEST_EVENTS=" + events}
			if mode == "matching" {
				cmd.Env = append(cmd.Env, "AGENTGUARD_CGROUP_ROOT="+filepath.Join(root, "scope"))
			}
			out, runErr := cmd.CombinedOutput()
			if runErr == nil {
				t.Fatal("fixture must exit at mismatch or fake go command")
			}
			data, err := os.ReadFile(events)
			if err != nil {
				t.Fatal(err)
			}
			want := "cmp " + launcher + "\n"
			if mode != "stale-launcher" {
				want += "cmp /usr/local/libexec/agentguard-bootstrap\n"
			}
			if mode == "matching" {
				want += "go\n"
			}
			if string(data) != want || strings.Contains(string(data), "mkdir\n") {
				t.Fatalf("unexpected operation order: %q, command output %q", data, out)
			}
		})
	}
}
