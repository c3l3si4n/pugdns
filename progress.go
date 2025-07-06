package main

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// ProgressDisplay manages a simple, reliable single-line progress display
type ProgressDisplay struct {
	mu             sync.Mutex
	startTime      time.Time
	totalItems     int64
	successItems   atomic.Int64
	failedItems    atomic.Int64
	retryingItems  atomic.Int64
	txPackets      atomic.Uint64
	rxPackets      atomic.Uint64
	queueSize      atomic.Int64
	lastUpdate     time.Time
	updateInterval time.Duration
	isActive       bool

	// Colors
	colorProgress func(a ...interface{}) string
	colorSuccess  func(a ...interface{}) string
	colorFailed   func(a ...interface{}) string
	colorRetrying func(a ...interface{}) string
	colorStats    func(a ...interface{}) string
}

func NewProgressDisplay(totalItems int64) *ProgressDisplay {
	pd := &ProgressDisplay{
		startTime:      time.Now(),
		totalItems:     totalItems,
		updateInterval: 100 * time.Millisecond,
		colorProgress:  color.New(color.FgHiBlue).SprintFunc(),
		colorSuccess:   color.New(color.FgGreen).SprintFunc(),
		colorFailed:    color.New(color.FgRed).SprintFunc(),
		colorRetrying:  color.New(color.FgYellow).SprintFunc(),
		colorStats:     color.New(color.FgCyan).SprintFunc(),
	}
	return pd
}

func (pd *ProgressDisplay) Start() {
	pd.mu.Lock()
	pd.isActive = true
	pd.mu.Unlock()
}

func (pd *ProgressDisplay) Stop() {
	pd.mu.Lock()
	pd.isActive = false
	pd.mu.Unlock()
	// Simply clear the current line and move to next line
	fmt.Print("\r\033[K")
	fmt.Println()
}

func (pd *ProgressDisplay) Update(success, failed, retrying int64, txPackets, rxPackets uint64, queueSize int64, currentRate float64) {
	pd.successItems.Store(success)
	pd.failedItems.Store(failed)
	pd.retryingItems.Store(retrying)
	pd.txPackets.Store(txPackets)
	pd.rxPackets.Store(rxPackets)
	pd.queueSize.Store(queueSize)

	pd.mu.Lock()
	defer pd.mu.Unlock()

	if !pd.isActive {
		return
	}

	now := time.Now()
	if now.Sub(pd.lastUpdate) < pd.updateInterval {
		return
	}
	pd.lastUpdate = now

	// Always use single-line display for reliability
	pd.renderSingleLine(currentRate)
}

func (pd *ProgressDisplay) renderProgressBar(percentage float64, width int) string {
	filled := int(float64(width) * percentage / 100)
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}

	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return pd.colorProgress(bar)
}

func (pd *ProgressDisplay) calculateETA(processed int64) string {
	if processed == 0 {
		return "calculating..."
	}

	elapsed := time.Since(pd.startTime)
	rate := float64(processed) / elapsed.Seconds()
	if rate == 0 {
		return "∞"
	}

	remaining := pd.totalItems - processed
	if remaining <= 0 {
		return "completing..."
	}

	eta := time.Duration(float64(remaining) / rate * float64(time.Second))

	if eta < time.Minute {
		return fmt.Sprintf("%ds", int(eta.Seconds()))
	} else if eta < time.Hour {
		return fmt.Sprintf("%dm %ds", int(eta.Minutes()), int(eta.Seconds())%60)
	} else {
		hours := int(eta.Hours())
		minutes := int(eta.Minutes()) % 60
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
}

// Removed multiline rendering - keeping only reliable single-line display

func (pd *ProgressDisplay) renderSingleLine(currentRate float64) {
	success := pd.successItems.Load()
	failed := pd.failedItems.Load()
	retrying := pd.retryingItems.Load()
	processed := success + failed
	percentage := float64(processed) / float64(pd.totalItems) * 100

	if percentage > 100 {
		percentage = 100
	}

	progressBar := pd.renderProgressBar(percentage, 15)

	// Calculate ETA
	eta := pd.calculateETA(processed)

	// Get elapsed time
	elapsed := formatDuration(time.Since(pd.startTime))

	// Enhanced single line with more info
	fmt.Printf("\r%s %s %.1f%% | ✓:%s ✗:%s ⟳:%s | %s qps | ETA:%s | %s",
		pd.colorStats("Progress:"),
		progressBar,
		percentage,
		pd.colorSuccess(formatNumber(success)),
		pd.colorFailed(formatNumber(failed)),
		pd.colorRetrying(formatNumber(retrying)),
		pd.colorStats(fmt.Sprintf("%.0f", currentRate)),
		pd.colorStats(eta),
		pd.colorStats(elapsed))
}

// Helper functions
func formatNumber(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1000000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	} else {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	} else {
		hours := int(d.Hours())
		minutes := int(d.Minutes()) % 60
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
}
