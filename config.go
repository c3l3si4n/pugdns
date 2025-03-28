package main

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
	NumWorkers    int // Added for potential future use
	PollTimeoutMs int // Added for poll timeout tuning
	Retries       int
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		NIC:           "",
		QueueID:       0,
		SrcMAC:        "",
		DstMAC:        "",
		SrcIP:         "",
		DomainName:    "google.com",
		Nameservers:   []string{"8.8.8.8", "8.8.4.4"},
		MaxBatchSize:  128,
		TextOutput:    true,
		OutputFile:    "results.json",
		NumWorkers:    1,
		PollTimeoutMs: 1, // Default to 1ms poll timeout
		Retries:       3,
	}
}
