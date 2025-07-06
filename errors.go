package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
)

// ErrorCategory represents a category of similar errors
type ErrorCategory struct {
	Name        string
	Count       atomic.Int64
	Examples    []string
	mu          sync.Mutex
	maxExamples int
}

// ErrorGrouper manages error categorization and grouping
type ErrorGrouper struct {
	categories map[string]*ErrorCategory
	mu         sync.RWMutex
}

func NewErrorGrouper() *ErrorGrouper {
	return &ErrorGrouper{
		categories: make(map[string]*ErrorCategory),
	}
}

// RecordError categorizes and records an error
func (eg *ErrorGrouper) RecordError(err error, context string) {
	if err == nil {
		return
	}

	category := categorizeError(err.Error())

	eg.mu.RLock()
	cat, exists := eg.categories[category]
	eg.mu.RUnlock()

	if !exists {
		eg.mu.Lock()
		// Double-check after acquiring write lock
		if cat, exists = eg.categories[category]; !exists {
			cat = &ErrorCategory{
				Name:        category,
				maxExamples: 5,
			}
			eg.categories[category] = cat
		}
		eg.mu.Unlock()
	}

	cat.Count.Add(1)

	// Store a few examples
	cat.mu.Lock()
	if len(cat.Examples) < cat.maxExamples {
		example := context
		if example == "" {
			example = err.Error()
		}
		cat.Examples = append(cat.Examples, example)
	}
	cat.mu.Unlock()
}

// GetSummary returns a formatted summary of all errors
func (eg *ErrorGrouper) GetSummary() string {
	eg.mu.RLock()
	defer eg.mu.RUnlock()

	if len(eg.categories) == 0 {
		return ""
	}

	var builder strings.Builder
	builder.WriteString("\n=== Error Summary ===\n")

	totalErrors := int64(0)
	for _, cat := range eg.categories {
		count := cat.Count.Load()
		totalErrors += count
	}

	builder.WriteString(fmt.Sprintf("Total errors: %d\n", totalErrors))

	for _, cat := range eg.categories {
		count := cat.Count.Load()
		builder.WriteString(fmt.Sprintf("\n%s: %d occurrences\n", cat.Name, count))

		cat.mu.Lock()
		for i, example := range cat.Examples {
			if i >= 3 { // Show max 3 examples
				remaining := len(cat.Examples) - 3
				if remaining > 0 {
					builder.WriteString(fmt.Sprintf("  ... and %d more\n", remaining))
				}
				break
			}
			builder.WriteString(fmt.Sprintf("  - %s\n", example))
		}
		cat.mu.Unlock()

		// Add helpful suggestions based on error type
		suggestion := getErrorSuggestion(cat.Name)
		if suggestion != "" {
			builder.WriteString(fmt.Sprintf("  → %s\n", suggestion))
		}
	}

	return builder.String()
}

// categorizeError determines the category of an error based on its message
func categorizeError(errMsg string) string {
	errLower := strings.ToLower(errMsg)

	switch {
	case strings.Contains(errLower, "permission denied"):
		return "Permission Denied"
	case strings.Contains(errLower, "no such device"):
		return "Device Not Found"
	case strings.Contains(errLower, "invalid nameserver"):
		return "Invalid Nameserver"
	case strings.Contains(errLower, "timeout"):
		return "Timeout"
	case strings.Contains(errLower, "connection refused"):
		return "Connection Refused"
	case strings.Contains(errLower, "packet size"):
		return "Packet Size Error"
	case strings.Contains(errLower, "preparing packet"):
		return "Packet Preparation Error"
	case strings.Contains(errLower, "xdp socket"):
		return "XDP Socket Error"
	case strings.Contains(errLower, "file") && strings.Contains(errLower, "open"):
		return "File Access Error"
	case strings.Contains(errLower, "memory"):
		return "Memory Error"
	case strings.Contains(errLower, "parse") || strings.Contains(errLower, "invalid"):
		return "Parse Error"
	default:
		// Try to extract a meaningful category from the error
		parts := strings.SplitN(errMsg, ":", 2)
		if len(parts) > 0 && len(parts[0]) < 50 {
			return strings.TrimSpace(parts[0])
		}
		return "Other Errors"
	}
}

// getErrorSuggestion provides helpful suggestions for common error types
func getErrorSuggestion(category string) string {
	suggestions := map[string]string{
		"Permission Denied":  "Try running with sudo or check CAP_NET_ADMIN capability",
		"Device Not Found":   "Check that the network interface exists with 'ip link show'",
		"Invalid Nameserver": "Verify nameserver IPs are valid (e.g., 8.8.8.8, 1.1.1.1)",
		"XDP Socket Error":   "Ensure your kernel supports XDP (4.18+) and driver has XDP support",
		"File Access Error":  "Check file permissions and that the file exists",
		"Memory Error":       "Try reducing batch size or check system memory availability",
		"Packet Size Error":  "Domain name might be too long or malformed",
	}

	return suggestions[category]
}

// ContextualError provides enhanced error messages with context
type ContextualError struct {
	Op      string // Operation that failed
	Context string // Additional context
	Err     error  // Underlying error
	Hint    string // Helpful hint for resolution
}

func (e *ContextualError) Error() string {
	var msg strings.Builder

	if e.Op != "" {
		msg.WriteString(e.Op)
		msg.WriteString(": ")
	}

	if e.Err != nil {
		msg.WriteString(e.Err.Error())
	}

	if e.Context != "" {
		msg.WriteString(" (")
		msg.WriteString(e.Context)
		msg.WriteString(")")
	}

	if e.Hint != "" {
		msg.WriteString("\n  → ")
		msg.WriteString(e.Hint)
	}

	return msg.String()
}

// WrapErrorWithContext creates a contextual error with helpful information
func WrapErrorWithContext(op string, err error, context string) error {
	if err == nil {
		return nil
	}

	hint := ""
	errLower := strings.ToLower(err.Error())

	// Add context-specific hints
	switch {
	case strings.Contains(errLower, "permission denied") && strings.Contains(op, "XDP"):
		hint = "Try running with sudo or add CAP_NET_ADMIN capability"
	case strings.Contains(errLower, "no such device"):
		hint = fmt.Sprintf("Interface '%s' not found. List interfaces with 'ip link show'", context)
	case strings.Contains(errLower, "address already in use"):
		hint = "Another process might be using the same XDP queue. Try a different queue ID"
	}

	return &ContextualError{
		Op:      op,
		Context: context,
		Err:     err,
		Hint:    hint,
	}
}
