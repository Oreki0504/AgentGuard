package linux

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSessionOwnsBootstrapAndChildDescriptors(t *testing.T) {
	for _, mode := range []string{"started", "not-started", "invalid-config", "source-failure"} {
		t.Run(mode, func(t *testing.T) {
			c := testConfig(t)
			bootstrap, err := os.CreateTemp(t.TempDir(), "bootstrap-fixture-")
			if err != nil {
				t.Fatal(err)
			}
			fd := bootstrap.Fd()
			if mode == "invalid-config" {
				c.Version = 1
			}
			if mode == "source-failure" {
				c.Files = append(c.Files, File{Source: filepath.Join(t.TempDir(), "missing"), Target: "/bin/missing"})
			}
			session, err := Prepare(c, bootstrap)
			fds := []uintptr{fd}
			if mode == "invalid-config" || mode == "source-failure" {
				if err == nil {
					session.Close()
					t.Fatal("invalid preparation passed")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				files := session.ExtraFiles()
				if len(files) != 3+len(c.Files)+len(c.Mounts) || files[len(files)-1] != bootstrap {
					t.Fatal("Bootstrap FD contract changed or duplicated")
				}
				for _, file := range files[:len(files)-1] {
					fds = append(fds, file.Fd())
				}
				readFD := session.read.Fd()
				if mode == "started" {
					if err := session.Started(123); err != nil {
						t.Fatal(err)
					}
					if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, readFD, syscall.F_GETFD, 0); errno != 0 {
						t.Fatal("host result channel closed at start")
					}
				} else {
					session.Close()
				}
			}
			for _, fd := range fds {
				if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0); errno != syscall.EBADF {
					t.Fatalf("owned FD %d remains open after %s: %v", fd, mode, errno)
				}
			}
		})
	}
	if session, err := Prepare(testConfig(t), nil); err == nil {
		session.Close()
		t.Fatal("missing Bootstrap accepted")
	}
}

func TestLauncherRejectsUnexpectedAppArmorEntry(t *testing.T) {
	for _, mode := range []string{"enforce", "complain", "unconfined", "stacked-label", "stacked", "ns-stacked", "missing-label", "missing-stacking"} {
		t.Run(mode, func(t *testing.T) {
			files := map[string]string{
				"/proc/self/attr/apparmor/current":          "agentguard-launcher (enforce)\n",
				"/sys/kernel/security/apparmor/.stacked":    "no\n",
				"/sys/kernel/security/apparmor/.ns_stacked": "no\n",
			}
			label := "/proc/self/attr/apparmor/current"
			switch mode {
			case "complain":
				files[label] = "agentguard-launcher (complain)\n"
			case "unconfined":
				files[label] = "unconfined\n"
			case "stacked-label":
				files[label] = "agentguard-launcher//&other (enforce)\n"
			case "stacked":
				files["/sys/kernel/security/apparmor/.stacked"] = "yes\n"
			case "ns-stacked":
				files["/sys/kernel/security/apparmor/.ns_stacked"] = "yes\n"
			case "missing-label":
				delete(files, label)
			case "missing-stacking":
				delete(files, "/sys/kernel/security/apparmor/.ns_stacked")
			}
			err := checkLauncherProfile(func(name string) ([]byte, error) {
				value, ok := files[name]
				if !ok {
					return nil, os.ErrNotExist
				}
				return []byte(value), nil
			})
			if (err == nil) != (mode == "enforce") {
				t.Fatalf("unexpected entry acceptance: %v", err)
			}
		})
	}
}
