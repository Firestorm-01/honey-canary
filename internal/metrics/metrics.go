package metrics

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
)

type Metrics struct {
	AlertsTotal   atomic.Int64
	ErrorsTotal   atomic.Int64
	HeartbeatsSent atomic.Int64
	server        *http.Server
}

func New() *Metrics {
	return &Metrics{}
}

func (m *Metrics) Start(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "# HELP honey_canary_alerts_total Total alerts fired\n")
		fmt.Fprintf(w, "# TYPE honey_canary_alerts_total counter\n")
		fmt.Fprintf(w, "honey_canary_alerts_total %d\n", m.AlertsTotal.Load())
		fmt.Fprintf(w, "# HELP honey_canary_errors_total Total monitor errors\n")
		fmt.Fprintf(w, "# TYPE honey_canary_errors_total counter\n")
		fmt.Fprintf(w, "honey_canary_errors_total %d\n", m.ErrorsTotal.Load())
		fmt.Fprintf(w, "# HELP honey_canary_heartbeats_total Total heartbeats sent\n")
		fmt.Fprintf(w, "# TYPE honey_canary_heartbeats_total counter\n")
		fmt.Fprintf(w, "honey_canary_heartbeats_total %d\n", m.HeartbeatsSent.Load())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	m.server = &http.Server{Addr: addr, Handler: mux}
	go m.server.ListenAndServe()
}

func (m *Metrics) Shutdown(ctx context.Context) error {
	if m.server != nil {
		return m.server.Shutdown(ctx)
	}
	return nil
}
