package e2e_test

import (
	"errors"
	"os/exec"
	"syscall"
	"unsafe"
)

var errBrowserJobObjectNotArmed = errors.New("browser job object was not armed")

func browserSysProcAttr() *syscall.SysProcAttr { return nil }

type browserTree struct {
	job  uintptr
	done bool
}

func newBrowserTree(cmd *exec.Cmd) *browserTree {
	tree := &browserTree{}
	if cmd == nil || cmd.Process == nil {
		return tree
	}
	job, _, _ := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		return tree
	}
	info := jobExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = uint32(jobObjectKillOnJobClose)
	if ok, _, _ := procSetInformationJobObject.Call(job, uintptr(jobObjectExtendedLimitInformation), uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); ok == 0 {
		procCloseHandle.Call(job)
		return tree
	}
	handle, _, _ := procOpenProcess.Call(uintptr(processSetQuota|processTerminate), 0, uintptr(uint32(cmd.Process.Pid)))
	if handle != 0 {
		if ok, _, _ := procAssignProcessToJobObject.Call(job, handle); ok != 0 {
			tree.job = job
		}
		procCloseHandle.Call(handle)
	}
	if tree.job == 0 {
		procCloseHandle.Call(job)
	}
	return tree
}
func (b *browserTree) kill() error {
	if b == nil || b.done {
		return nil
	}
	b.done = true
	if b.job == 0 {
		return errBrowserJobObjectNotArmed
	}
	procCloseHandle.Call(b.job)
	b.job = 0
	return nil
}

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procCloseHandle              = kernel32.NewProc("CloseHandle")

	jobObjectExtendedLimitInformation = 9
	jobObjectKillOnJobClose           = 0x2000
	processSetQuota                   = 0x0100
	processTerminate                  = 0x0001
)

type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}
