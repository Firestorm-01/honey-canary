//go:build windows

package process

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procSetConsoleTitleW = modKernel32.NewProc("SetConsoleTitleW")
)

func MasqueradeProcess(newName string) error {
	namePtr, err := syscall.UTF16PtrFromString(newName)
	if err != nil {
		return err
	}
	procSetConsoleTitleW.Call(uintptr(unsafe.Pointer(namePtr)))
	return nil
}

func populateProcessInfo(info *ProcessInfo) error {
	pid := uint32(info.PID)
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false, pid,
	)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(handle)

	var exePath [windows.MAX_PATH]uint16
	size := uint32(len(exePath))
	if err := windows.QueryFullProcessImageName(handle, 0, &exePath[0], &size); err == nil {
		info.Executable = windows.UTF16ToString(exePath[:size])
	}

	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if tokenUser, err := token.GetTokenUser(); err == nil {
			if account, domain, _, err := tokenUser.User.Sid.LookupAccount(""); err == nil {
				info.Username = domain + "\\" + account
			}
			info.UID = tokenUser.User.Sid.String()
		}
	}
	return nil
}

func SetResourceLimits(maxMemoryMB int) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject failed: %w", err)
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
	info.ProcessMemoryLimit = uintptr(maxMemoryMB) * 1024 * 1024
	if _, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		return fmt.Errorf("SetInformationJobObject failed: %w", err)
	}
	currentProcess, _ := windows.GetCurrentProcess()
	return windows.AssignProcessToJobObject(job, currentProcess)
}
