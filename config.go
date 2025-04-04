package main

import (
	"time"
)

// Config holds all program configuration
type Config struct {
	NIC           string
	QueueID       int
	SrcMAC        string
	DstMAC        string
	SrcIP         string
	DomainName    string
	Nameservers   []string
	OutputFile    string
	MaxBatchSize  int
	Verbose       bool
	TextOutput    bool
	CodesToSkip   []int
	NumWorkers    int
	RetryTimeout  time.Duration
	PollTimeoutMs int
	Retries       int
	RateLimitPPS  int // Added: Target packets per second for the sender
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		NIC:           "",
		QueueID:       0,
		SrcMAC:        "",
		DstMAC:        "",
		RetryTimeout:  5 * time.Second,
		SrcIP:         "",
		DomainName:    "google.com",
		Nameservers:   []string{"8.8.8.8", "8.8.4.4"},
		MaxBatchSize:  128,
		TextOutput:    true,
		OutputFile:    "results.json",
		CodesToSkip:   []int{},
		NumWorkers:    1,
		PollTimeoutMs: 1,
		Retries:       3,
		RateLimitPPS:  100000, // Default rate limit: 100k PPS
	}
}
