//go:build linux

package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"honey-canary/internal/process"
)

type InotifyMonitor struct {
	fd         int
	watchPaths []string
	eventTypes []EventType
	events     chan FileEvent
	errors     chan error
	done       chan struct{}
	wg         sync.WaitGroup
	watchDescs map[int]string // wd -> path
	mu         sync.Mutex
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

	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1 failed: %w", err)
	}

	return &InotifyMonitor{
		fd:         fd,
		watchPaths: watchPaths,
		eventTypes: eventTypes,
		events:     make(chan FileEvent, 256),
		errors:     make(chan error, 32),
		done:       make(chan struct{}),
		watchDescs: make(map[int]string),
		selfHeal:   selfHeal,
		content:    content,
	}, nil
}

func (m *InotifyMonitor) Start(ctx context.Context) error {
	mask := m.buildMask()
	for _, p := range m.watchPaths {
		wd, err := unix.InotifyAddWatch(m.fd, p, mask)
		if err != nil {
			return fmt.Errorf("inotify_add_watch(%s) failed: %w", p, err)
		}
		m.mu.Lock()
		m.watchDescs[wd] = p
		m.mu.Unlock()
	}

	m.wg.Add(1)
	go m.readEvents(ctx)
	return nil
}

func (m *InotifyMonitor) buildMask() uint32 {
	var mask uint32
	for _, et := range m.eventTypes {
		switch et {
		case EventRead, EventAccess:
			mask |= unix.IN_ACCESS | unix.IN_OPEN
		case EventWrite:
			mask |= unix.IN_MODIFY | unix.IN_CLOSE_WRITE
		case EventChmod:
			mask |= unix.IN_ATTRIB
		case EventRename:
			mask |= unix.IN_MOVE_SELF | unix.IN_MOVED_FROM | unix.IN_MOVED_TO
		case EventDelete:
			mask |= unix.IN_DELETE_SELF
		}
	}
	return mask
}

func (m *InotifyMonitor) readEvents(ctx context.Context) {
	defer m.wg.Done()
	buf := make([]byte, 4096)
	pollFds := []unix.PollFd{{Fd: int32(m.fd), Events: unix.POLLIN}}

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		default:
		}

		n, err := unix.Poll(pollFds, 200)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			select {
			case m.errors <- fmt.Errorf("poll: %w", err):
			default:
			}
			continue
		}
		if n == 0 {
			continue
		}

		nr, err := unix.Read(m.fd, buf)
		if err != nil {
			if err == unix.EAGAIN {
				continue
			}
			select {
			case m.errors <- fmt.Errorf("read: %w", err):
			default:
			}
			continue
		}

		offset := 0
		for offset+unix.SizeofInotifyEvent <= nr {
			// Safe aligned read — SizeofInotifyEvent is 16, buf is heap-allocated
			ev := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			nameLen := int(ev.Len)
			if offset+unix.SizeofInotifyEvent+nameLen > nr {
				break
			}

			m.mu.Lock()
			watchedPath, ok := m.watchDescs[int(ev.Wd)]
			m.mu.Unlock()

			if ok {
				et := m.mapMask(ev.Mask)
				if et != "" {
					fe := FileEvent{
						Timestamp: time.Now().UTC(),
						Path:      watchedPath,
						EventType: et,
						PID:       -1,
					}
					m.enrichFromProc(&fe)

					select {
					case m.events <- fe:
					default:
						select {
						case m.errors <- fmt.Errorf("event buffer full, dropping event for %s", watchedPath):
						default:
						}
					}

					// Self-heal: recreate canary if deleted
					if m.selfHeal && (et == EventDelete || et == EventRename) {
						go m.healFile(watchedPath)
					}
				}
			}

			offset += unix.SizeofInotifyEvent + nameLen
		}
	}
}

func (m *InotifyMonitor) mapMask(mask uint32) EventType {
	switch {
	case mask&(unix.IN_ACCESS|unix.IN_OPEN) != 0:
		return EventAccess
	case mask&(unix.IN_MODIFY|unix.IN_CLOSE_WRITE) != 0:
		return EventWrite
	case mask&unix.IN_ATTRIB != 0:
		return EventChmod
	case mask&(unix.IN_MOVE_SELF|unix.IN_MOVED_FROM|unix.IN_MOVED_TO) != 0:
		return EventRename
	case mask&unix.IN_DELETE_SELF != 0:
		return EventDelete
	default:
		return ""
	}
}

func (m *InotifyMonitor) enrichFromProc(fe *FileEvent) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var pid int
		if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == fe.Path {
				fe.PID = pid
				if info, err := process.GetProcessInfo(pid); err == nil {
					fe.ProcessName = info.ProcessName
					fe.Username = info.Username
					fe.UID = info.UID
					fe.Executable = info.Executable
					fe.Cmdline = info.Cmdline
				}
				return
			}
		}
	}
}

func (m *InotifyMonitor) healFile(path string) {
	time.Sleep(500 * time.Millisecond)
	body := m.content
	if body == "" {
		body = "CANARY_TOKEN\n"
	}
	_ = os.WriteFile(path, []byte(body), 0644)
	// Re-add inotify watch for healed file
	mask := m.buildMask()
	if wd, err := unix.InotifyAddWatch(m.fd, path, mask); err == nil {
		m.mu.Lock()
		m.watchDescs[wd] = path
		m.mu.Unlock()
	}
}

func (m *InotifyMonitor) Events() <-chan FileEvent { return m.events }
func (m *InotifyMonitor) Errors() <-chan error     { return m.errors }

func (m *InotifyMonitor) Close() error {
	close(m.done)
	m.wg.Wait()
	m.mu.Lock()
	for wd := range m.watchDescs {
		unix.InotifyRmWatch(m.fd, uint32(wd))
	}
	m.mu.Unlock()
	close(m.events)
	close(m.errors)
	return unix.Close(m.fd)
}
