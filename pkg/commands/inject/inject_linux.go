package inject

import "C"
import (
	"syscall"

	"github.com/tfogal/ptrace"
)

type LinuxInjection struct {
	Target      int
	Successful  bool
	Payload     []byte
	LibraryPath string
}

func (l *LinuxInjection) TargetPid() int {
	return l.Target
}

func (l *LinuxInjection) Success() bool {
	return l.Successful
}

func (l *LinuxInjection) Shellcode() []byte {
	return l.Payload
}

func (l *LinuxInjection) SharedLib() string {
	return l.LibraryPath
}

func injectShellcode(pid int, shellcode []byte) (LinuxInjection, error) {
	oldregs := syscall.PtraceRegs{}
	res := LinuxInjection{}
	// Try to attach to the target process
	traceeHandle, err := ptrace.Attach(pid)

	if err != nil {
		return res, err
	}

	var w syscall.WaitStatus
	r := syscall.Rusage{}

	// wait for the target process to signal
	wpid, err := syscall.Wait4(pid, &w, 0, &r)

	if err != nil {
		return res, err
	}

	// Get the registers to save their state
	registers, err := traceeHandle.GetRegs()

	if err != nil {
		return res, err
	}

	oldregs = registers

	oldcode := C.malloc(C.sizeof_char * 9076)

}
