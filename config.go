package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration
type Config struct {
	// Network settings
	NIC         string   `yaml:"interface" json:"interface"`
	QueueID     int      `yaml:"queue_id" json:"queue_id"`
	SrcMAC      string   `yaml:"src_mac" json:"src_mac"`
	DstMAC      string   `yaml:"dst_mac" json:"dst_mac"`
	SrcIP       string   `yaml:"src_ip" json:"src_ip"`
	Nameservers []string `yaml:"nameservers" json:"nameservers"`

	// Query settings
	DomainName   string        `yaml:"domain" json:"domain"`
	RetryTimeout time.Duration `yaml:"retry_timeout" json:"retry_timeout"`
	Retries      int           `yaml:"retries" json:"retries"`

	// Performance settings
	MaxBatchSize  int `yaml:"max_batch_size" json:"max_batch_size"`
	PollTimeoutMs int `yaml:"poll_timeout_ms" json:"poll_timeout_ms"`

	// Output settings
	OutputFile  string `yaml:"output_file" json:"output_file"`
	CodesToSkip []int  `yaml:"skip_codes" json:"skip_codes"`

	// Display settings
	Verbose       bool   `yaml:"verbose" json:"verbose"`
	StatsInterval string `yaml:"stats_interval" json:"stats_interval"`
	Quiet         bool   `yaml:"quiet" json:"quiet"`

	// Advanced settings
	DryRun bool `yaml:"dry_run" json:"dry_run"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		NIC:           "", // Leave empty to auto-discover
		QueueID:       0,
		Nameservers:   []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"},
		RetryTimeout:  2 * time.Second,
		Retries:       10,
		MaxBatchSize:  65536,
		PollTimeoutMs: 1,
		OutputFile:    "",
		CodesToSkip:   []int{},
		Verbose:       false,
		StatsInterval: "500ms",
	}
}

// LoadConfigFile loads configuration from a YAML or JSON file
func LoadConfigFile(filename string) (*Config, error) {
	config := DefaultConfig()

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, config)
	case ".json":
		err = json.Unmarshal(data, config)
	default:
		// Try YAML first, then JSON
		err = yaml.Unmarshal(data, config)
		if err != nil {
			err = json.Unmarshal(data, config)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	return config, nil
}

// SaveConfigFile saves the current configuration to a file
func (c *Config) SaveConfigFile(filename string) error {
	var data []byte
	var err error

	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".yaml", ".yml":
		data, err = yaml.Marshal(c)
	case ".json":
		data, err = json.MarshalIndent(c, "", "  ")
	default:
		// Default to YAML
		data, err = yaml.Marshal(c)
	}

	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	return os.WriteFile(filename, data, 0644)
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.NIC == "" {
		return fmt.Errorf("network interface cannot be empty")
	}

	if c.MaxBatchSize <= 0 {
		return fmt.Errorf("max batch size must be positive")
	}

	if c.PollTimeoutMs < 0 {
		return fmt.Errorf("poll timeout cannot be negative")
	}

	if c.Retries < 0 {
		return fmt.Errorf("retries cannot be negative")
	}

	if len(c.Nameservers) == 0 {
		return fmt.Errorf("at least one nameserver must be specified")
	}

	// Validate nameserver IPs
	for _, ns := range c.Nameservers {
		if !isValidIP(ns) {
			return fmt.Errorf("invalid nameserver IP: %s", ns)
		}
	}

	return nil
}

// isValidIP checks if a string is a valid IP address
func isValidIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if part == "" {
			return false
		}
		num := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
			num = num*10 + int(ch-'0')
			if num > 255 {
				return false
			}
		}
	}
	return true
}

// GenerateExampleConfig creates an example configuration file
func GenerateExampleConfig(filename string) error {
	example := &Config{
		NIC:           "", // Leave empty to auto-discover
		QueueID:       0,
		SrcMAC:        "",
		DstMAC:        "",
		SrcIP:         "",
		Nameservers:   []string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"},
		RetryTimeout:  2 * time.Second,
		Retries:       10,
		MaxBatchSize:  65536,
		PollTimeoutMs: 1,
		OutputFile:    "results.jsonl",
		CodesToSkip:   []int{2, 5}, // SERVFAIL, REFUSED
		Verbose:       false,
	}

	return example.SaveConfigFile(filename)
}
