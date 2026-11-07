package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
)

func main() {
	if value, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 39 /* PR_GET_NO_NEW_PRIVS */, 0, 0, 0, 0, 0); errno != 0 || value != 1 {
		panic(fmt.Sprintf("NNP query: value=%d errno=%v", value, errno))
	}
	if value, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 21 /* PR_GET_SECCOMP */, 0, 0, 0, 0, 0); errno != 0 || value != 2 {
		panic(fmt.Sprintf("seccomp query: value=%d errno=%v", value, errno))
	}
	if len(os.Args) == 2 && os.Args[1] == "child" {
		fmt.Print("go-child")
		return
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			data := make([]byte, 1024*1024)
			for j := range data {
				data[j] = byte(j)
			}
			runtime.KeepAlive(data)
		}()
	}
	workers.Wait()
	if _, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0); err != syscall.EPERM {
		panic(fmt.Sprintf("network syscall: %v", err))
	}
	self, err := os.Executable()
	if err != nil {
		panic(err)
	}
	output, err := exec.Command(self, "child").CombinedOutput()
	if err != nil || string(output) != "go-child" {
		panic(fmt.Sprintf("Go child: %q %v", output, err))
	}
	output, err = exec.Command("/bin/sh", "-c", "printf shell-child").CombinedOutput()
	if err != nil || string(output) != "shell-child" {
		panic(fmt.Sprintf("shell child: %q %v", output, err))
	}
}
