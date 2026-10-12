package runtime

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// rootfsAllocation records the exact directory created by this Runtime. The
// host directory stays empty: all guest content lives in a private tmpfs.
type rootfsAllocation struct {
	path string
	info os.FileInfo
}

func allocateRootfs(base string) (*rootfsAllocation, error) {
	name, err := os.MkdirTemp(base, "agentguard-rootfs-")
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(name)
	if err != nil {
		_ = os.Remove(name)
		return nil, err
	}
	return &rootfsAllocation{path: name, info: info}, nil
}

func (r *rootfsAllocation) remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(r.path)
	if err != nil {
		return err
	}
	if !os.SameFile(r.info, info) {
		return fmt.Errorf("rootfs allocation identity changed; retained %s", r.path)
	}
	// cgroup emptiness is necessary but not sufficient. Reject any mount
	// visible to the host at/below the allocation, including a bind of it.
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()
	if err := checkMountReferences(f, r.path); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Never recursively delete unexpected contents.
	return os.Remove(r.path)
}

func checkMountReferences(mountinfo io.Reader, rootfs string) error {
	s := bufio.NewScanner(mountinfo)
	s.Buffer(make([]byte, 4096), 1024*1024)
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 6 {
			return fmt.Errorf("invalid mountinfo")
		}
		for _, field := range []string{fields[3], fields[4]} {
			name := filepath.Clean(replacer.Replace(field))
			if name == rootfs || strings.HasPrefix(name, rootfs+"/") {
				return fmt.Errorf("rootfs still has a host mount reference; retained %s", rootfs)
			}
		}
	}
	return s.Err()
}
