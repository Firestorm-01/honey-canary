package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"honey-canary/internal/monitor"
)

type AuditEntry struct {
	Timestamp   time.Time          `json:"timestamp"`
	EventType   monitor.EventType  `json:"event_type"`
	Path        string             `json:"path"`
	PID         int                `json:"pid"`
	ProcessName string             `json:"process_name"`
	Username    string             `json:"username"`
	UID         string             `json:"uid"`
	Executable  string             `json:"executable"`
	Cmdline     string             `json:"cmdline"`
}

type AuditLogger struct {
	mu   sync.Mutex
	file *os.File
}

func New(path string) (*AuditLogger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log %s: %w", path, err)
	}
	return &AuditLogger{file: f}, nil
}

func (l *AuditLogger) Log(event monitor.FileEvent) error {
	entry := AuditEntry{
		Timestamp:   event.Timestamp,
		EventType:   event.EventType,
		Path:        event.Path,
		PID:         event.PID,
		ProcessName: event.ProcessName,
		Username:    event.Username,
		UID:         event.UID,
		Executable:  event.Executable,
		Cmdline:     event.Cmdline,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = fmt.Fprintf(l.file, "%s\n", data)
	return err
}

func (l *AuditLogger) Close() error {
	return l.file.Close()
}
