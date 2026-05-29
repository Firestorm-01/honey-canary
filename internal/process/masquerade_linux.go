//go:build linux

package process

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MasqueradeProcess changes the process name visible in /proc/self/comm
func MasqueradeProcess(newName string) error {
	nameBytes := make([]byte, 16)
	copy(nameBytes, newName)
	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PRCTL,
		syscall.PR_SET_NAME,
		uintptr(unsafe.Pointer(&nameBytes[0])),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("PR_SET_NAME failed: %v", errno)
	}
	return nil
}

func populateProcessInfo(info *ProcessInfo) error {
	pid := info.PID

	if comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		info.ProcessName = strings.TrimSpace(string(comm))
	}

	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		info.Executable = exe
	}

	if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		info.Cmdline = strings.TrimRight(
			strings.ReplaceAll(string(cmdline), "\x00", " "), " ")
	}

	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil // best-effort; non-fatal
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.UID = fields[1]
				if uid, err := strconv.Atoi(info.UID); err == nil {
					if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
						info.Username = u.Username
					}
				}
			}
			break
		}
	}
	return nil
}

// SetResourceLimits enforces a memory ceiling via RLIMIT_AS
func SetResourceLimits(maxMemoryMB int) error {
	limit := uint64(maxMemoryMB) * 1024 * 1024
	return unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{Cur: limit, Max: limit})
}
