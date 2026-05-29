//go:build windows

package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"honey-canary/internal/process"
)

type WindowsMonitor struct {
	watchPaths []string
	dirHandles []windows.Handle
	eventTypes []EventType
	events     chan FileEvent
	errors     chan error
	done       chan struct{}
	wg         sync.WaitGroup
	selfHeal   bool
	content    string
}

func NewMonitor(watchPaths []string, eventTypes []EventType, selfHeal bool, content string) (Monitor, error) {
	for _, p := range watchPaths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			dir := filepath.Dir(p)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
			body := content
			if body == "" {
				body = "CANARY_TOKEN\n"
			}
			if err := os.WriteFile(p, []byte(body), 0644); err != nil {
				return nil, fmt.Errorf("failed to create canary file %s: %w", p, err)
			}
		}
	}
	return &WindowsMonitor{
		watchPaths: watchPaths,
		eventTypes: eventTypes,
		events:     make(chan FileEvent, 256),
		errors:     make(chan error, 32),
		done:       make(chan struct{}),
		selfHeal:   selfHeal,
		content:    content,
	}, nil
}

func (m *WindowsMonitor) Start(ctx context.Context) error {
	for _, p := range m.watchPaths {
		watchDir := filepath.Dir(p)
		dirPath, err := windows.UTF16PtrFromString(watchDir)
		if err != nil {
			return err
		}
		handle, err := windows.CreateFile(
			dirPath,
			windows.FILE_LIST_DIRECTORY,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
			0,
		)
		if err != nil {
			return fmt.Errorf("CreateFile(%s) failed: %w", watchDir, err)
		}
		m.dirHandles = append(m.dirHandles, handle)

		targetFile := filepath.Base(p)
		m.wg.Add(1)
		go m.watchDir(ctx, handle, p, targetFile)
	}
	return nil
}

func (m *WindowsMonitor) watchDir(ctx context.Context, handle windows.Handle, fullPath, targetFile string) {
	defer m.wg.Done()
	buf := make([]byte, 64*1024)
	var overlapped windows.Overlapped
	event, _ := windows.CreateEvent(nil, 1, 0, nil)
	defer windows.CloseHandle(event)
	overlapped.HEvent = event

	filter := m.buildFilter()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		default:
		}

		var bytesReturned uint32
		_ = windows.ReadDirectoryChanges(handle, &buf[0], uint32(len(buf)), false, filter, &bytesReturned, &overlapped, 0)

		result, _ := windows.WaitForSingleObject(event, 500)
		if result == windows.WAIT_TIMEOUT {
			continue
		}
		windows.GetOverlappedResult(handle, &overlapped, &bytesReturned, false)

		offset := uint32(0)
		for offset < bytesReturned {
			info := (*windows.FILE_NOTIFY_INFORMATION)(unsafe.Pointer(&buf[offset]))
			nameLen := info.FileNameLength / 2
			nameSlice := (*[1 << 20]uint16)(unsafe.Pointer(&info.FileName[0]))[:nameLen:nameLen]
			fileName := windows.UTF16ToString(nameSlice)

			if fileName == targetFile {
				et := mapWindowsAction(info.Action)
				if et != "" {
					fe := FileEvent{
						Timestamp: time.Now().UTC(),
						Path:      fullPath,
						EventType: et,
					}
					// best-effort process enrichment via snapshot
					_ = process.GetProcessInfo // future: ETW integration
					select {
					case m.events <- fe:
					default:
					}
					if m.selfHeal && (et == EventDelete || et == EventRename) {
						go m.healFile(fullPath)
					}
				}
			}
			if info.NextEntryOffset == 0 {
				break
			}
			offset += info.NextEntryOffset
		}
		windows.ResetEvent(event)
	}
}

func (m *WindowsMonitor) buildFilter() uint32 {
	var f uint32
	for _, et := range m.eventTypes {
		switch et {
		case EventRead, EventAccess:
			f |= 0x00000020 // FILE_NOTIFY_CHANGE_LAST_ACCESS
		case EventWrite:
			f |= 0x00000008 | 0x00000010 // SIZE | LAST_WRITE
		case EventChmod:
			f |= 0x00000004 | 0x00000100 // ATTRIBUTES | SECURITY
		case EventRename, EventDelete:
			f |= 0x00000001 // FILE_NOTIFY_CHANGE_FILE_NAME
		}
	}
	return f
}

func mapWindowsAction(action uint32) EventType {
	switch action {
	case 3:
		return EventWrite
	case 2:
		return EventDelete
	case 4, 5:
		return EventRename
	default:
		return EventAccess
	}
}

func (m *WindowsMonitor) healFile(path string) {
	time.Sleep(500 * time.Millisecond)
	body := m.content
	if body == "" {
		body = "CANARY_TOKEN\n"
	}
	_ = os.WriteFile(path, []byte(body), 0644)
}

func (m *WindowsMonitor) Events() <-chan FileEvent { return m.events }
func (m *WindowsMonitor) Errors() <-chan error     { return m.errors }

func (m *WindowsMonitor) Close() error {
	close(m.done)
	m.wg.Wait()
	for _, h := range m.dirHandles {
		windows.CloseHandle(h)
	}
	close(m.events)
	close(m.errors)
	return nil
}
