package linux

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// OpenTrustedExecutable shares the launcher's existing root-owned path trust
// rule and returns a pinned handle for the Bootstrap source. No content hashes
// or workload-controlled trust roots are introduced.
func OpenTrustedExecutable(name string) (*os.File, error) {
	if err := ValidateTrustedExecutable(name); err != nil {
		return nil, err
	}
	return openSource(name, false)
}

// ValidateTrustedExecutable retains the metadata-only launcher validation;
// callers that need to copy Bootstrap use OpenTrustedExecutable to pin it.
func ValidateTrustedExecutable(name string) error {
	if !cleanAbsolute(name) || name == "/" {
		return fmt.Errorf("trusted executable must have a clean absolute path")
	}
	for p := name; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("inspect trusted executable: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("executable and ancestors must be root-owned and not group/world writable")
		}
		if p == name && (!info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0) {
			return fmt.Errorf("trusted executable must be a regular, non-setuid executable")
		}
		if p == "/" {
			break
		}
	}
	return nil
}
