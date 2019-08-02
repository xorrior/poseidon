package inject

import (
	"syscall"

	"github.com/tfogal/ptrace"
)

type LinuxInjection struct {
	TargetPid int
	Success   bool
	Shellcode []byte
}

func injectShellcode(pid int, shellcode []byte) (bool, error) {
	// Try to attach to the target process
	traceeHandle, err := ptrace.Attach(pid)

	if err != nil {
		return false, err
	}

	wpid, err := syscall.Wait4(pid)
}
