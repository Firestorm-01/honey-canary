package heartbeat

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"honey-canary/internal/alerter"
	"honey-canary/internal/metrics"
	"honey-canary/internal/process"
)

type Heartbeat struct {
	interval time.Duration
	alerter  *alerter.Alerter
	metrics  *metrics.Metrics
	start    time.Time
	done     chan struct{}
}

func New(intervalSeconds int, a *alerter.Alerter, m *metrics.Metrics) *Heartbeat {
	return &Heartbeat{
		interval: time.Duration(intervalSeconds) * time.Second,
		alerter:  a,
		metrics:  m,
		start:    time.Now(),
		done:     make(chan struct{}),
	}
}

func (h *Heartbeat) Start(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.done:
			return
		case <-ticker.C:
			h.send(ctx)
		}
	}
}

func (h *Heartbeat) send(ctx context.Context) {
	memBytes := process.MemoryStats()
	uptime := time.Since(h.start).Round(time.Second)
	status := fmt.Sprintf(
		"✅ Canary active | Uptime: %s | Memory: %.2f MB | Goroutines: %d | Alerts sent: %d",
		uptime,
		float64(memBytes)/1024/1024,
		runtime.NumGoroutine(),
		h.metrics.AlertsTotal.Load(),
	)
	if err := h.alerter.Heartbeat(ctx, status); err != nil {
		fmt.Printf("[heartbeat] send failed: %v\n", err)
	} else {
		h.metrics.HeartbeatsSent.Add(1)
	}
}

func (h *Heartbeat) Stop() { close(h.done) }
