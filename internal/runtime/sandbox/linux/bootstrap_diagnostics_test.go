package linux

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
)

// This gated test observes the original closed-stdin fixture. It never changes
// registers, syscall results, Bootstrap bytes or the production observer.
func traceSecureStdio(pid int, base traceOps) (traceOps, error) {
	file, err := elf.Open(bootstrapEntry)
	if err != nil {
		return base, err
	}
	defer file.Close()
	symbols, err := file.Symbols()
	if err != nil {
		return base, err
	}
	var standardFDs elf.Symbol
	for _, symbol := range symbols {
		if symbol.Name == "__libc_check_standard_fds" {
			standardFDs = symbol
		}
	}
	if standardFDs.Size == 0 {
		return base, fmt.Errorf("missing libc stdio symbol")
	}
	if _, err := os.Lstat("/dev/full"); !os.IsNotExist(err) {
		return base, fmt.Errorf("expected private rootfs without /dev/full: %v", err)
	}
	peek := func(address uint64) (uint64, error) {
		var data [8]byte
		if _, err := syscall.PtracePeekData(pid, uintptr(address), data[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(data[:]), nil
	}
	cstring := func(address uint64) (string, error) {
		var value []byte
		for len(value) < 4096 {
			word, err := peek(address + uint64(len(value)))
			if err != nil {
				return "", err
			}
			for i := 0; i < 8; i++ {
				b := byte(word >> (8 * i))
				if b == 0 {
					return string(value), nil
				}
				value = append(value, b)
			}
		}
		return "", fmt.Errorf("unterminated syscall path")
	}
	var slide uint64
	secure, closed, refused := false, false, false
	inSyscall := false
	pending := ""
	ops := base
	ops.options = func(pid, flags int) error {
		return base.options(pid, flags|syscall.PTRACE_O_TRACESYSGOOD)
	}
	ops.resume = func(pid, signal int) error {
		var regs syscall.PtraceRegs
		if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
			return err
		}
		argc, err := peek(regs.Rsp)
		if err != nil || argc != 1 {
			return fmt.Errorf("unexpected bootstrap initial stack: argc=%d err=%v", argc, err)
		}
		// argc + argv[0] + argv NULL, followed by an empty environment.
		env, err := peek(regs.Rsp + 24)
		if err != nil || env != 0 {
			return fmt.Errorf("unexpected bootstrap initial environment")
		}
		for address, count := regs.Rsp+32, 0; count < 128; address, count = address+16, count+1 {
			kind, err := peek(address)
			if err != nil {
				return err
			}
			value, err := peek(address + 8)
			if err != nil {
				return err
			}
			if kind == 0 {
				break
			}
			if kind == 23 { // AT_SECURE
				secure = value == 1
			}
			if kind == 9 { // AT_ENTRY: relocation of this exact static PIE.
				slide = value - file.Entry
			}
		}
		if !secure || slide == 0 {
			return fmt.Errorf("expected secure static-PIE startup: secure=%t slide=%#x", secure, slide)
		}
		fmt.Printf("diagnostic AT_SECURE=1 slide=%#x /dev/full=absent; observing syscalls\n", slide)
		return syscall.PtraceSyscall(pid, signal)
	}
	ops.wait = func(want int, status *syscall.WaitStatus, flags int, usage *syscall.Rusage) (int, error) {
		got, err := base.wait(want, status, flags, usage)
		if err != nil || got == 0 || !status.Stopped() {
			return got, err
		}
		if status.StopSignal() == syscall.Signal(int(syscall.SIGTRAP)|0x80) {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
				return 0, err
			}
			if !inSyscall {
				pending = ""
				if regs.Orig_rax == syscall.SYS_FCNTL && regs.Rdi == 0 && regs.Rsi == syscall.F_GETFD {
					pending = "stdin F_GETFD"
				}
				if regs.Orig_rax == syscall.SYS_OPENAT || regs.Orig_rax == syscall.SYS_OPEN {
					address := regs.Rsi
					if regs.Orig_rax == syscall.SYS_OPEN {
						address = regs.Rdi
					}
					path, err := cstring(address)
					if err != nil {
						return 0, err
					}
					if path == "/dev/full" {
						pending = "open /dev/full"
					}
				}
			} else if pending != "" {
				result := int64(regs.Rax)
				fmt.Printf("diagnostic %s result=%d\n", pending, result)
				if pending == "stdin F_GETFD" {
					closed = result == -int64(syscall.EBADF)
				} else {
					refused = result == -int64(syscall.ENOENT) || result == -int64(syscall.EACCES)
				}
			}
			inSyscall = !inSyscall
			return 0, syscall.PtraceSyscall(pid, 0)
		}
		if status.StopSignal() == syscall.SIGSEGV {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
				return 0, err
			}
			opcode, err := peek(regs.Rip)
			start := slide + standardFDs.Value
			if err != nil || !secure || !closed || !refused || byte(opcode) != 0xf4 ||
				regs.Rip < start || regs.Rip >= start+standardFDs.Size {
				return 0, fmt.Errorf("unconfirmed secure-stdio failure: rip=%#x opcode=%#x closed=%t refused=%t err=%v", regs.Rip, opcode, closed, refused, err)
			}
			fmt.Fprintf(os.Stderr, "secure stdio diagnosis confirmed: AT_SECURE=1 fd0=EBADF /dev/full refused; SIGSEGV at __libc_check_standard_fds+%#x HLT (RIP=%#x)\n", regs.Rip-start, regs.Rip)
		}
		return got, nil
	}
	return ops, nil
}
