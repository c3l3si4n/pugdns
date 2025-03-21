package main

// Config holds all program configuration
type Config struct {
	NIC         string
	QueueID     int
	SrcMAC      string
	DstMAC      string
	SrcIP       string
	DstIP       string
	DomainName  string
	Nameservers []string
	Verbose     bool
	TextOutput  bool
	OutputFile  string
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		NIC:         "",
		QueueID:     0,
		SrcMAC:      "",
		DstMAC:      "",
		SrcIP:       "",
		DstIP:       "",
		DomainName:  "google.com",
		Nameservers: []string{"8.8.8.8", "8.8.4.4"},
		TextOutput:  false,
		OutputFile:  "results.json",
	}
}
