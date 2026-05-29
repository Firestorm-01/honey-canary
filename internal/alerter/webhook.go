package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"honey-canary/internal/monitor"
)

type WebhookSender struct {
	webhookURL string
	authHeader string
	hmacSecret string
	client     *http.Client
}

func NewWebhookSender(webhookURL, authHeader, hmacSecret string, client *http.Client) *WebhookSender {
	return &WebhookSender{
		webhookURL: webhookURL,
		authHeader: authHeader,
		hmacSecret: hmacSecret,
		client:     client,
	}
}

type webhookPayload struct {
	Type      string             `json:"type"`
	Timestamp string             `json:"timestamp"`
	Event     *monitor.FileEvent `json:"event,omitempty"`
	Message   string             `json:"message,omitempty"`
	Status    string             `json:"status,omitempty"`
}

func (w *WebhookSender) Send(ctx context.Context, event monitor.FileEvent) error {
	p := webhookPayload{
		Type:      "canary_alert",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Event:     &event,
	}
	return w.post(ctx, p)
}

func (w *WebhookSender) SendDeathGasp(ctx context.Context, reason string) error {
	return w.post(ctx, webhookPayload{
		Type:      "death_gasp",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Message:   reason,
	})
}

func (w *WebhookSender) SendHeartbeat(ctx context.Context, status string) error {
	return w.post(ctx, webhookPayload{
		Type:      "heartbeat",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Status:    status,
	})
}

func (w *WebhookSender) post(ctx context.Context, p webhookPayload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.authHeader != "" {
		req.Header.Set("Authorization", w.authHeader)
	}
	if sig := HMACSign(w.hmacSecret, body); sig != "" {
		req.Header.Set("X-Canary-Signature", "sha256="+sig)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
