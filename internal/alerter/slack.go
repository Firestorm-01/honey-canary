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

type SlackSender struct {
	webhookURL string
	client     *http.Client
}

func NewSlackSender(webhookURL string, client *http.Client) *SlackSender {
	return &SlackSender{webhookURL: webhookURL, client: client}
}

type slackMessage struct {
	Text        string       `json:"text,omitempty"`
	Attachments []attachment `json:"attachments,omitempty"`
}

type attachment struct {
	Color  string  `json:"color"`
	Title  string  `json:"title"`
	Text   string  `json:"text"`
	Fields []field `json:"fields,omitempty"`
	Footer string  `json:"footer"`
	Ts     int64   `json:"ts"`
}

type field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

func (s *SlackSender) Send(ctx context.Context, event monitor.FileEvent) error {
	fields := []field{
		{Title: "File", Value: event.Path, Short: false},
		{Title: "Event", Value: string(event.EventType), Short: true},
	}
	if event.PID > 0 {
		fields = append(fields, field{Title: "PID", Value: fmt.Sprintf("%d", event.PID), Short: true})
	}
	if event.Username != "" {
		fields = append(fields, field{Title: "User", Value: fmt.Sprintf("%s (UID: %s)", event.Username, event.UID), Short: true})
	}
	if event.ProcessName != "" {
		fields = append(fields, field{Title: "Process", Value: event.ProcessName, Short: true})
	}
	if event.Executable != "" {
		fields = append(fields, field{Title: "Executable", Value: event.Executable, Short: false})
	}

	msg := slackMessage{
		Text: "🚨 CANARY ALERT 🚨",
		Attachments: []attachment{{
			Color:  "danger",
			Title:  "Honey File Accessed!",
			Text:   "A monitored canary file has been touched.",
			Fields: fields,
			Footer: "Honey-Canary Monitor",
			Ts:     event.Timestamp.Unix(),
		}},
	}
	return s.post(ctx, msg)
}

func (s *SlackSender) SendDeathGasp(ctx context.Context, reason string) error {
	msg := slackMessage{
		Text: "💀 DEATH GASP 💀",
		Attachments: []attachment{{
			Color:  "#000000",
			Title:  "Canary Process Terminated!",
			Text:   fmt.Sprintf("Process killed.\nReason: %s", reason),
			Footer: "FINAL TRANSMISSION",
			Ts:     time.Now().Unix(),
		}},
	}
	return s.post(ctx, msg)
}

func (s *SlackSender) SendHeartbeat(ctx context.Context, status string) error {
	msg := slackMessage{
		Attachments: []attachment{{
			Color:  "good",
			Title:  "💓 Heartbeat",
			Text:   status,
			Footer: "Honey-Canary Monitor",
			Ts:     time.Now().Unix(),
		}},
	}
	return s.post(ctx, msg)
}

func (s *SlackSender) post(ctx context.Context, msg slackMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned %d", resp.StatusCode)
	}
	return nil
}
