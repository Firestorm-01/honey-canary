package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Canary     CanaryConfig     `yaml:"canary"`
	Stealth    StealthConfig    `yaml:"stealth"`
	Heartbeat  HeartbeatConfig  `yaml:"heartbeat"`
	Alerting   AlertingConfig   `yaml:"alerting"`
	RateLimit  RateLimitConfig  `yaml:"ratelimit"`
	AntiTamper AntiTamperConfig `yaml:"antitamper"`
	Audit      AuditConfig      `yaml:"audit"`
	Metrics    MetricsConfig    `yaml:"metrics"`
}

type CanaryConfig struct {
	WatchPaths []string `yaml:"watchpaths"`
	Events     []string `yaml:"events"`
	SelfHeal   bool     `yaml:"selfheal"`
	Content    string   `yaml:"content"`
}

type StealthConfig struct {
	ProcessName string `yaml:"processname"`
	MaxMemoryMB int    `yaml:"maxmemorymb"`
}

type HeartbeatConfig struct {
	IntervalSeconds int    `yaml:"intervalseconds"`
	Endpoint        string `yaml:"endpoint"`
}

type AlertingConfig struct {
	Primary    AlertChannel `yaml:"primary"`
	Backup     AlertChannel `yaml:"backup"`
	HMACSecret string       `yaml:"hmacsecret"`
}

type AlertChannel struct {
	Type       string `yaml:"type"`
	WebhookURL string `yaml:"webhookurl"`
	AuthHeader string `yaml:"authheader,omitempty"`
}

type RateLimitConfig struct {
	MaxAlerts     int `yaml:"maxalerts"`
	WindowSeconds int `yaml:"windowseconds"`
}

type AntiTamperConfig struct {
	ConfigPath string `yaml:"configpath"`
	DeathGasp  bool   `yaml:"deathgasp"`
}

type AuditConfig struct {
	LogPath string `yaml:"logpath"`
	Enabled bool   `yaml:"enabled"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if len(c.Canary.WatchPaths) == 0 {
		return fmt.Errorf("canary.watchpaths must have at least one entry")
	}
	if len(c.Canary.Events) == 0 {
		return fmt.Errorf("canary.events must have at least one entry")
	}
	if c.Alerting.Primary.WebhookURL == "" {
		return fmt.Errorf("alerting.primary.webhookurl is required")
	}
	validTypes := map[string]bool{"discord": true, "slack": true, "webhook": true}
	if !validTypes[c.Alerting.Primary.Type] {
		return fmt.Errorf("alerting.primary.type must be discord, slack, or webhook; got %q", c.Alerting.Primary.Type)
	}
	if c.RateLimit.MaxAlerts == 0 {
		c.RateLimit.MaxAlerts = 5
	}
	if c.RateLimit.WindowSeconds == 0 {
		c.RateLimit.WindowSeconds = 60
	}
	return nil
}
