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

type DiscordSender struct {
	webhookURL string
	client     *http.Client
}

func NewDiscordSender(webhookURL string, client *http.Client) *DiscordSender {
	return &DiscordSender{webhookURL: webhookURL, client: client}
}

type discordMessage struct {
	Content string         `json:"content,omitempty"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Color       int            `json:"color"`
	Fields      []embedField   `json:"fields,omitempty"`
	Timestamp   string         `json:"timestamp"`
	Footer      *embedFooter   `json:"footer,omitempty"`
}

type embedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type embedFooter struct {
	Text string `json:"text"`
}

func (d *DiscordSender) Send(ctx context.Context, event monitor.FileEvent) error {
	fields := []embedField{
		{Name: "📁 File", Value: event.Path, Inline: false},
		{Name: "⚡ Event", Value: string(event.EventType), Inline: true},
	}
	if event.PID > 0 {
		fields = append(fields, embedField{Name: "🔢 PID", Value: fmt.Sprintf("%d", event.PID), Inline: true})
	}
	if event.Username != "" {
		fields = append(fields, embedField{Name: "👤 User", Value: fmt.Sprintf("%s (UID: %s)", event.Username, event.UID), Inline: true})
	}
	if event.ProcessName != "" {
		fields = append(fields, embedField{Name: "📦 Process", Value: event.ProcessName, Inline: true})
	}
	if event.Executable != "" {
		fields = append(fields, embedField{Name: "🗂️ Executable", Value: event.Executable, Inline: false})
	}
	if event.Cmdline != "" {
		cmd := event.Cmdline
		if len(cmd) > 200 {
			cmd = cmd[:200] + "…"
		}
		fields = append(fields, embedField{Name: "💻 Cmdline", Value: "`" + cmd + "`", Inline: false})
	}

	msg := discordMessage{
		Content: "🚨 **CANARY ALERT** 🚨",
		Embeds: []discordEmbed{{
			Title:       "Honey File Accessed!",
			Description: "A monitored canary file has been touched.",
			Color:       0xFF0000,
			Fields:      fields,
			Timestamp:   event.Timestamp.Format(time.RFC3339),
			Footer:      &embedFooter{Text: "Honey-Canary Monitor"},
		}},
	}
	return d.post(ctx, msg)
}

func (d *DiscordSender) SendDeathGasp(ctx context.Context, reason string) error {
	msg := discordMessage{
		Content: "💀 **DEATH GASP** 💀",
		Embeds: []discordEmbed{{
			Title:       "Canary Process Terminated!",
			Description: fmt.Sprintf("The Honey-Canary process is being killed!\n\nReason: %s", reason),
			Color:       0x000000,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Footer:      &embedFooter{Text: "FINAL TRANSMISSION"},
		}},
	}
	return d.post(ctx, msg)
}

func (d *DiscordSender) SendHeartbeat(ctx context.Context, status string) error {
	msg := discordMessage{
		Embeds: []discordEmbed{{
			Title:       "💓 Heartbeat",
			Description: status,
			Color:       0x00FF00,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Footer:      &embedFooter{Text: "Honey-Canary Monitor"},
		}},
	}
	return d.post(ctx, msg)
}

func (d *DiscordSender) post(ctx context.Context, msg discordMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("discord returned %d", resp.StatusCode)
	}
	return nil
}
