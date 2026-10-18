package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReopenVerifiedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace")

	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}

	pinned, err := openSource(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()

	// The original directory must be accepted.
	current, err := reopenVerifiedDirectory(path, pinned)
	if err != nil {
		t.Fatalf("valid directory rejected: %v", err)
	}
	current.Close()

	// Replace the pathname with a different directory.
	if err := os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}

	// The original FD is still valid, but the path
	// now points to a different inode.
	current, err = reopenVerifiedDirectory(path, pinned)
	if err == nil {
		current.Close()
		t.Fatal("replaced directory was accepted")
	}
}
