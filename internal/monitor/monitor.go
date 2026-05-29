package monitor

import (
	"context"
	"fmt"
	"time"
)

type EventType string

const (
	EventRead   EventType = "READ"
	EventWrite  EventType = "WRITE"
	EventChmod  EventType = "CHMOD"
	EventRename EventType = "RENAME"
	EventDelete EventType = "DELETE"
	EventAccess EventType = "ACCESS"
)

type FileEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Path        string    `json:"path"`
	EventType   EventType `json:"event_type"`
	PID         int       `json:"pid"`
	ProcessName string    `json:"process_name"`
	Username    string    `json:"username"`
	UID         string    `json:"uid"`
	Executable  string    `json:"executable"`
	Cmdline     string    `json:"cmdline"`
}

type Monitor interface {
	Start(ctx context.Context) error
	Events() <-chan FileEvent
	Errors() <-chan error
	Close() error
}

func ParseEventTypes(events []string) ([]EventType, error) {
	var result []EventType
	for _, e := range events {
		switch e {
		case "read":
			result = append(result, EventRead)
		case "write":
			result = append(result, EventWrite)
		case "chmod":
			result = append(result, EventChmod)
		case "rename":
			result = append(result, EventRename)
		case "delete":
			result = append(result, EventDelete)
		case "access":
			result = append(result, EventAccess)
		default:
			return nil, fmt.Errorf("unknown event type: %s", e)
		}
	}
	return result, nil
}
