package ratelimit

import (
	"sync"
	"time"
)

type entry struct {
	count     int
	windowEnd time.Time
}

// Limiter is a per-key sliding-window rate limiter.
type Limiter struct {
	mu      sync.Mutex
	entries map[string]*entry
	max     int
	window  time.Duration
}

func New(max int, window time.Duration) *Limiter {
	return &Limiter{
		entries: make(map[string]*entry),
		max:     max,
		window:  window,
	}
}

// Allow returns true if the key is within the rate limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	e, ok := l.entries[key]
	if !ok || now.After(e.windowEnd) {
		l.entries[key] = &entry{count: 1, windowEnd: now.Add(l.window)}
		return true
	}
	if e.count >= l.max {
		return false
	}
	e.count++
	return true
}

// Cleanup removes stale entries; call periodically.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, e := range l.entries {
		if now.After(e.windowEnd) {
			delete(l.entries, k)
		}
	}
}
