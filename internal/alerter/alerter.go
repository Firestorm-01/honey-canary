package alerter

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"honey-canary/internal/config"
	"honey-canary/internal/monitor"
)

type AlertSender interface {
	Send(ctx context.Context, event monitor.FileEvent) error
	SendDeathGasp(ctx context.Context, reason string) error
	SendHeartbeat(ctx context.Context, status string) error
}

type Alerter struct {
	primary    AlertSender
	backup     AlertSender
	hmacSecret string
}

func NewAlerter(cfg config.AlertingConfig) (*Alerter, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	primary, err := createSender(cfg.Primary, client, cfg.HMACSecret)
	if err != nil {
		return nil, fmt.Errorf("primary alerter: %w", err)
	}

	var backup AlertSender
	if cfg.Backup.WebhookURL != "" {
		backup, err = createSender(cfg.Backup, client, cfg.HMACSecret)
		if err != nil {
			return nil, fmt.Errorf("backup alerter: %w", err)
		}
	}

	return &Alerter{
		primary:    primary,
		backup:     backup,
		hmacSecret: cfg.HMACSecret,
	}, nil
}

func createSender(cfg config.AlertChannel, client *http.Client, hmacSecret string) (AlertSender, error) {
	switch cfg.Type {
	case "discord":
		return NewDiscordSender(cfg.WebhookURL, client), nil
	case "slack":
		return NewSlackSender(cfg.WebhookURL, client), nil
	case "webhook":
		return NewWebhookSender(cfg.WebhookURL, cfg.AuthHeader, hmacSecret, client), nil
	default:
		return nil, fmt.Errorf("unknown alert type: %s", cfg.Type)
	}
}

func (a *Alerter) Alert(ctx context.Context, event monitor.FileEvent) error {
	err := a.primary.Send(ctx, event)
	if err != nil && a.backup != nil {
		return a.backup.Send(ctx, event)
	}
	return err
}

func (a *Alerter) DeathGasp(ctx context.Context, reason string) error {
	err1 := a.primary.SendDeathGasp(ctx, reason)
	var err2 error
	if a.backup != nil {
		err2 = a.backup.SendDeathGasp(ctx, reason)
	}
	if err1 != nil && err2 != nil {
		return fmt.Errorf("all death gasp attempts failed: primary=%v backup=%v", err1, err2)
	}
	return nil
}

func (a *Alerter) Heartbeat(ctx context.Context, status string) error {
	return a.primary.SendHeartbeat(ctx, status)
}

// HMACSign signs a payload with the configured HMAC-SHA256 secret.
// Signature is returned as hex and placed in X-Canary-Signature header.
func HMACSign(secret string, payload []byte) string {
	if secret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// FormatEventJSON serialises an event for signing.
func FormatEventJSON(event monitor.FileEvent) ([]byte, error) {
	return json.Marshal(event)
}
