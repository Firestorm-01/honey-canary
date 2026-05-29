package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"honey-canary/internal/alerter"
	"honey-canary/internal/config"
	"honey-canary/internal/heartbeat"
	"honey-canary/internal/logger"
	"honey-canary/internal/metrics"
	"honey-canary/internal/monitor"
	"honey-canary/internal/process"
	"honey-canary/internal/ratelimit"
)

var (
	configPath = flag.String("config", "config.yaml", "Path to configuration file")
	version    = "2.0.0"
)

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if err := applyStealth(cfg.Stealth); err != nil {
		fmt.Fprintf(os.Stderr, "warning: stealth setup failed: %v\n", err)
	}

	alert, err := alerter.NewAlerter(cfg.Alerting)
	if err != nil {
		fmt.Fprintf(os.Stderr, "alerter error: %v\n", err)
		os.Exit(1)
	}

	m := metrics.New()
	if cfg.Metrics.Enabled {
		m.Start(cfg.Metrics.Addr)
		fmt.Printf("Metrics: http://%s/metrics\n", cfg.Metrics.Addr)
	}

	var auditLog *logger.AuditLogger
	if cfg.Audit.Enabled && cfg.Audit.LogPath != "" {
		auditLog, err = logger.New(cfg.Audit.LogPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: audit log failed to open: %v\n", err)
		} else {
			defer auditLog.Close()
		}
	}

	rl := ratelimit.New(cfg.RateLimit.MaxAlerts, time.Duration(cfg.RateLimit.WindowSeconds)*time.Second)
	go func() {
		for range time.Tick(5 * time.Minute) {
			rl.Cleanup()
		}
	}()

	eventTypes, err := monitor.ParseEventTypes(cfg.Canary.Events)
	if err != nil {
		fmt.Fprintf(os.Stderr, "event type error: %v\n", err)
		os.Exit(1)
	}

	mon, err := monitor.NewMonitor(cfg.Canary.WatchPaths, eventTypes, cfg.Canary.SelfHeal, cfg.Canary.Content)
	if err != nil {
		fmt.Fprintf(os.Stderr, "monitor error: %v\n", err)
		os.Exit(1)
	}
	defer mon.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := mon.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "monitor start error: %v\n", err)
		os.Exit(1)
	}

	hb := heartbeat.New(cfg.Heartbeat.IntervalSeconds, alert, m)
	go hb.Start(ctx)

	setupSignalHandler(cfg, alert, cancel)

	fmt.Printf("Honey-Canary v%s started\n", version)
	fmt.Printf("Watching %d path(s): %v\n", len(cfg.Canary.WatchPaths), cfg.Canary.WatchPaths)
	fmt.Printf("Self-heal: %v | Events: %v\n", cfg.Canary.SelfHeal, cfg.Canary.Events)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		eventLoop(ctx, mon, alert, auditLog, rl, m)
	}()

	<-ctx.Done()
	wg.Wait()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	m.Shutdown(shutCtx)

	fmt.Println("Honey-Canary shutdown complete")
}

func applyStealth(cfg config.StealthConfig) error {
	if cfg.MaxMemoryMB > 0 {
		debug.SetMemoryLimit(int64(cfg.MaxMemoryMB) * 1024 * 1024)
		if err := process.SetResourceLimits(cfg.MaxMemoryMB); err != nil {
			return fmt.Errorf("memory limit: %w", err)
		}
	}
	if cfg.ProcessName != "" {
		if err := process.MasqueradeProcess(cfg.ProcessName); err != nil {
			return fmt.Errorf("masquerade: %w", err)
		}
	}
	debug.SetGCPercent(20)
	runtime.GOMAXPROCS(1)
	return nil
}

func setupSignalHandler(cfg *config.Config, alert *alerter.Alerter, cancel context.CancelFunc) {
	if !cfg.AntiTamper.DeathGasp {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)
		go func() {
			<-sigChan
			cancel()
		}()
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		sig := <-sigChan
		reason := fmt.Sprintf("received signal %v (PID %d)", sig, os.Getpid())
		dCtx, dCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer dCancel()
		if err := alert.DeathGasp(dCtx, reason); err != nil {
			fmt.Fprintf(os.Stderr, "death gasp failed: %v\n", err)
		}
		cancel()
	}()
}

func eventLoop(
	ctx context.Context,
	mon monitor.Monitor,
	alert *alerter.Alerter,
	auditLog *logger.AuditLogger,
	rl *ratelimit.Limiter,
	m *metrics.Metrics,
) {
	for {
		select {
		case <-ctx.Done():
			return

		case event, ok := <-mon.Events():
			if !ok {
				return
			}

			// Structured audit log (always, regardless of rate limit)
			if auditLog != nil {
				if err := auditLog.Log(event); err != nil {
					fmt.Fprintf(os.Stderr, "audit log error: %v\n", err)
				}
			}

			// Console output
			fmt.Printf("[%s] ALERT %s on %s (PID: %d User: %s Process: %s)\n",
				event.Timestamp.Format(time.RFC3339),
				event.EventType, event.Path,
				event.PID, event.Username, event.ProcessName,
			)

			// Rate-limit alerts by source key
			key := fmt.Sprintf("%d|%s", event.PID, event.Username)
			if !rl.Allow(key) {
				fmt.Printf("[%s] rate-limited alert for key %s\n",
					event.Timestamp.Format(time.RFC3339), key)
				continue
			}

			m.AlertsTotal.Add(1)

			aCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := alert.Alert(aCtx, event); err != nil {
				fmt.Fprintf(os.Stderr, "alert send error: %v\n", err)
				m.ErrorsTotal.Add(1)
			}
			cancel()

		case err, ok := <-mon.Errors():
			if !ok {
				return
			}
			fmt.Fprintf(os.Stderr, "monitor error: %v\n", err)
			m.ErrorsTotal.Add(1)
		}
	}
}
