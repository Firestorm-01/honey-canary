package process

import (
	"fmt"
	"os/user"
	"runtime"
)

// ProcessInfo contains information about a process that accessed the canary
type ProcessInfo struct {
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	Username    string `json:"username"`
	UID         string `json:"uid"`
	Executable  string `json:"executable"`
	Cmdline     string `json:"cmdline"`
}

// GetCurrentUser returns the current user's name and UID
func GetCurrentUser() (string, string, error) {
	u, err := user.Current()
	if err != nil {
		return "", "", err
	}
	return u.Username, u.Uid, nil
}

// GetProcessInfo retrieves detailed process information by PID.
// Platform-specific implementation is in masquerade_linux.go / masquerade_windows.go
func GetProcessInfo(pid int) (*ProcessInfo, error) {
	info := &ProcessInfo{PID: pid}
	if err := populateProcessInfo(info); err != nil {
		return nil, fmt.Errorf("failed to get process info for PID %d: %w", pid, err)
	}
	return info, nil
}

// MemoryStats returns current heap allocation in bytes
func MemoryStats() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}
