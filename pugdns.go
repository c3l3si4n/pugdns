/*
pugdns: a fast DNS bruteforcer
*/
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/rand"
	"golang.org/x/sys/unix"
)

type PacketInfo struct {
	Domain      string // FQDN
	PacketBytes []byte
	Attempt     int
}

// DomainStatus tracks the state of each domain query
type DomainStatus struct {
	AttemptsMade int
	Responded    bool
	LastAttempt  time.Time
}

var domainStatesMutex sync.Mutex

// Map to track domain status
var domainStates map[string]*DomainStatus

type StatsModel struct {
	totalDomains     int // NEW: Total unique domains
	respondedDomains int // NEW: Domains that got a response
	retryingDomains  int // NEW: Domains currently being retried
	failedDomains    int // NEW: Domains that failed after max retries

	packetsSentRaw      uint64  // Renamed from totalPackets (raw XDP completed)
	packetsPerSecRaw    uint64  // Renamed from packetsPerSec (raw XDP rate)
	avgPacketsPerSecRaw float64 // Renamed from avgPacketsPerSec (raw XDP avg rate)
	receivedPackets     uint64  // Still relevant

	progressBar progress.Model
	startTime   time.Time
	duration    float64
	width       int
	height      int
	quitting    bool
}

var globalConfig *Config

// Initial model setup (minor change)
func (m StatsModel) Init() tea.Cmd {
	// You might want to set totalDomains here if known, or update it later
	return tea.Batch(
		tickCmd(),
	)
}

// A command that waits for the next tick
func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

var neededNumberOfPackets float64

type tickMsg time.Time

// Update handles updates to the model
func (m StatsModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	// ... (KeyMsg, WindowSizeMsg remain the same) ...

	case statsUpdateMsg:
		m.totalDomains = msg.totalDomains
		m.respondedDomains = msg.respondedDomains
		m.retryingDomains = msg.retryingDomains
		m.failedDomains = msg.failedDomains

		m.packetsSentRaw = msg.packetsSentRaw
		m.packetsPerSecRaw = msg.packetsPerSecRaw
		m.avgPacketsPerSecRaw = msg.avgPacketsPerSecRaw
		m.receivedPackets = msg.receivedPackets // Get latest global count

		m.duration = msg.duration

		// Update progress bar based on responded domains
		progress := 0.0
		if m.totalDomains > 0 {
			progress = float64(m.respondedDomains+m.failedDomains) / float64(m.totalDomains)
		}
		m.progressBar.SetPercent(progress)

		return m, nil

	case tickMsg:
		// Request a stats update on every tick
		return m, tea.Batch(tickCmd()) // Continue ticking
	}

	return m, nil
}

// --- View Modifications ---
func (m StatsModel) View() string {
	if m.quitting {
		return "Processing complete!\n"
	}

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		Render("DNS QUERY STATUS")

	// More detailed stats
	stats := fmt.Sprintf(
		"\nDomains: %d | Responded: %d | Retrying: %d | Failed: %d"+
			"\nRaw Sent: %d | Raw Rate: %d pps | Raw Avg: %.2f pps"+
			"\nReceived (BPF): %d"+ // Show BPF received count separately
			"\nRuntime: %.1f seconds",
		m.totalDomains, m.respondedDomains, m.retryingDomains, m.failedDomains,
		m.packetsSentRaw, m.packetsPerSecRaw, m.avgPacketsPerSecRaw,
		m.receivedPackets, // Use the updated global value
		m.duration)

	progressVal := 0.0
	if m.totalDomains > 0 {
		// Progress represents completed domains (responded or failed)
		progressVal = float64(m.respondedDomains+m.failedDomains) / float64(m.totalDomains)
	}
	progress := "\nProgress (Domains Completed):\n" + m.progressBar.ViewAs(progressVal)

	help := "\nPress q to quit"

	return lipgloss.JoinVertical(lipgloss.Left, title, stats, progress, help)
}

type statsUpdateMsg struct {
	totalDomains     int
	respondedDomains int
	retryingDomains  int
	failedDomains    int

	packetsSentRaw      uint64
	packetsPerSecRaw    uint64
	avgPacketsPerSecRaw float64
	receivedPackets     uint64 // Use the global atomic counter for this

	duration float64
}

// readDomainsFromFile reads domains/nameservers from a file, one per line
func readDomainsFromFile(filename string) ([]string, error) {
	if filename == "" {
		return nil, nil
	}

	items := []string{}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			items = append(items, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return items, nil
}

var receivedPackets uint64

func packetSender(xsk *xdp.Socket, packetQueue <-chan PacketInfo, stopSignal <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	log.Println("Packet sender started.")

	maxBatchSize := 128                       // How many packets to try sending at once
	pollTimeout := globalConfig.PollTimeoutMs // Use configured timeout

	for {
		select {
		case <-stopSignal:
			log.Println("Packet sender received stop signal. Finalizing...")
			finalizeTransmission(xsk)
			log.Println("Packet sender finished.")
			return
		default:
			// 1. Handle Completions first to free descriptors
			_, _, pollErr := xsk.Poll(pollTimeout)
			if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR {
				log.Printf("Sender Poll error: %v", pollErr)
				// Maybe sleep briefly on persistent errors?
				time.Sleep(5 * time.Millisecond)
			}
			numCompleted := xsk.NumCompleted()
			if numCompleted > 0 {
				xsk.Complete(numCompleted)
				if globalConfig.Verbose {
					log.Printf("Sender: Completed %d packets", numCompleted)
				}
			}

			// 2. Get Available Descriptors
			freeSlots := xsk.NumFreeTxSlots()
			if freeSlots == 0 {
				// No slots, yield and loop back to poll/check stop signal
				runtime.Gosched()
				continue
			}

			descsToRequest := freeSlots
			if descsToRequest > maxBatchSize {
				descsToRequest = maxBatchSize
			}

			descs := xsk.GetDescs(descsToRequest, false)
			if len(descs) == 0 {
				// Should not happen if freeSlots > 0, but check anyway
				runtime.Gosched()
				continue
			}

			// 3. Fill Descriptors from Queue (Non-blocking)
			packetsToSend := make([]PacketInfo, 0, len(descs))
			for i := 0; i < len(descs); i++ {
				select {
				case pktInfo, ok := <-packetQueue:
					if !ok {
						// Channel closed, means manager wants to stop
						log.Println("Packet queue closed. Sender stopping.")
						finalizeTransmission(xsk) // Finalize before exiting
						log.Println("Packet sender finished.")
						return
					}
					packetsToSend = append(packetsToSend, pktInfo)
				default:
					// Queue is empty, stop filling descriptors for this batch
					goto sendBatch // Use goto to jump to sending code below
				}
			}

		sendBatch:
			if len(packetsToSend) == 0 {
				// No packets read from queue, release descriptors we got
				// NOTE: xdp library doesn't have an explicit "ReleaseDescs"
				// They are implicitly released on next GetDescs or socket close.
				// Yield to avoid busy loop if queue remains empty.
				runtime.Gosched()
				continue
			}

			// Fill the frames for the packets we dequeued
			descsFilled := 0
			for i, pktInfo := range packetsToSend {
				if len(pktInfo.PacketBytes) == 0 {
					log.Printf("Warning: Empty packet bytes for domain %s", pktInfo.Domain)
					continue
				}
				frame := xsk.GetFrame(descs[i])
				if len(frame) < len(pktInfo.PacketBytes) {
					log.Printf("Error: Frame size (%d) too small for packet (%d bytes) for domain %s. Skipping.", len(frame), len(pktInfo.PacketBytes), pktInfo.Domain)
					// This packet won't be sent. Manager needs to retry it.
					// Mark the descriptor len as 0? Or just don't increment descsFilled?
					// Safest is to not increment descsFilled.
					continue // Skip to next packet
				}
				frameLen := copy(frame, pktInfo.PacketBytes)
				descs[i].Len = uint32(frameLen)
				descsFilled++
			}

			// 4. Transmit the Batch
			if descsFilled > 0 {
				numSubmitted := xsk.Transmit(descs[:descsFilled])
				if globalConfig.Verbose {
					log.Printf("Sender: Attempted to submit %d, actually submitted %d packets", descsFilled, numSubmitted)
				}
				if numSubmitted != descsFilled {
					log.Printf("Warning: Sender failed to submit %d packets (%d/%d)", descsFilled-numSubmitted, numSubmitted, descsFilled)
					// The manager will eventually retry the domains for the packets that failed submission.
				}
			}
		} // End select
	} // End for
}

// statsCollector handles collecting and displaying transmission statistics
func transmitPackets(xsk *xdp.Socket, initialDomains []string, config *Config) error {
	log.Println("Initializing transmission manager...")
	domainStates = make(map[string]*DomainStatus)
	totalDomains := len(initialDomains)
	neededNumberOfPackets = float64(totalDomains) // For progress bar based on domains

	// Prepare initial domain states
	fqdnDomains := make([]string, totalDomains)
	for i, domain := range initialDomains {
		fqdn := dns.Fqdn(domain)
		fqdnDomains[i] = fqdn
		domainStates[fqdn] = &DomainStatus{
			AttemptsMade: 0,
			Responded:    false,
		}
	}

	// --- Channels and Concurrency Setup ---
	// --- Channels and Concurrency Setup ---
	packetQueue := make(chan PacketInfo, 2048)
	stopSender := make(chan struct{})
	stopStats := make(chan struct{})
	programDone := make(chan struct{})
	var senderWg sync.WaitGroup
	statsUpdateChan := make(chan StatsUpdateData, 10) // Buffered channel for stats

	// --- Start Statistics Collector ---
	// Pass the statsUpdateChan for receiving updates
	go statsCollector(xsk, statsUpdateChan, stopStats, programDone, config)

	// --- Start Packet Sender Goroutine ---
	senderWg.Add(1)
	go packetSender(xsk, packetQueue, stopSender, &senderWg)

	// --- Management Logic ---
	log.Printf("Preparing and queuing initial %d domains...", totalDomains)
	rng := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))

	// Resolve MACs once
	link, err := netlink.LinkByName(config.NIC)
	if err != nil {
		return fmt.Errorf("manager couldn't find interface %s: %v", config.NIC, err)
	}
	srcMAC, dstMAC, err := ResolveMACAddresses(config, link)
	if err != nil {
		return fmt.Errorf("manager error resolving MAC addresses: %v", err)
	}
	srcIP := net.ParseIP(config.SrcIP)

	// Prepare and queue initial batch
	initialPacketsPrepared := 0
	for _, fqdn := range fqdnDomains {
		pktInfo, err := prepareSinglePacket(fqdn, srcIP, srcMAC, dstMAC, config.Nameservers, rng)
		if err != nil {
			log.Printf("Error preparing initial packet for %s: %v. Marking as failed.", fqdn, err)
			domainStatesMutex.Lock()
			domainStates[fqdn].Responded = false             // Ensure it's false
			domainStates[fqdn].AttemptsMade = config.Retries // Mark as failed
			domainStatesMutex.Unlock()
			continue
		}

		pktInfo.Attempt = 1
		packetQueue <- pktInfo
		initialPacketsPrepared++
		domainStatesMutex.Lock()
		domainStates[fqdn].AttemptsMade = 1
		domainStates[fqdn].LastAttempt = time.Now()
		domainStatesMutex.Unlock()
	}
	log.Printf("Queued %d initial packets.", initialPacketsPrepared)

	// --- Main Management Loop ---
	startTime := time.Now()
	maxRuntime := 120 * time.Second
	ticker := time.NewTicker(500 * time.Millisecond) // Check more frequently?
	defer ticker.Stop()
	timeout := time.After(maxRuntime)

	var lastRawStats xdp.Stats // Track previous raw stats for rate calculation

loop:
	for {
		select {
		case <-ticker.C:
			now := time.Now() // Get time once
			duration := now.Sub(startTime).Seconds()

			// --- Check Domain Status, Update Responded flag, and Queue Retries ---
			domainStatesMutex.Lock() // Lock before checking/modifying domainStates

			respCount := 0
			failCount := 0
			retryPendCount := 0
			domainsToRetry := []string{} // Collect domains needing retry

			for fqdn, status := range domainStates {
				if status.Responded {
					respCount++
					continue // Already done
				}
				if status.AttemptsMade >= config.Retries {
					failCount++
					continue // Failed all retries
				}

				// ***>>> ADD THIS CACHE CHECK <<<***
				if _, found := cache.Get(fqdn); found {
					status.Responded = true // Mark as responded!
					respCount++
					if config.Verbose {
						log.Printf("Domain %s marked as responded based on cache check.", fqdn)
					}
					continue // Move to next domain
				}
				// ***>>> END OF CACHE CHECK <<<***

				// *** Check for Retry Needed (Example: Retry after 1s) ***
				retryTimeout := 1 * time.Second // Adjust as needed
				if !status.LastAttempt.IsZero() && now.Sub(status.LastAttempt) > retryTimeout {
					domainsToRetry = append(domainsToRetry, fqdn)
					// It will be counted below after potential requeue attempt
				} else {
					retryPendCount++ // Still pending/waiting for initial response or retry timeout
				}
			}
			totalDoms := len(domainStates) // Get total count inside lock
			domainStatesMutex.Unlock()     // Unlock after initial check/status update

			// --- Queue Retries (Outside the main status lock) ---
			queuedRetries := 0
			if len(domainsToRetry) > 0 {
				// Re-resolve MACs or pass them if needed
				linkRetry, _ := netlink.LinkByName(config.NIC)
				srcMACRetry, dstMACRetry, _ := ResolveMACAddresses(config, linkRetry)
				srcIPRetry := net.ParseIP(config.SrcIP)
				rngRetry := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))

				domainStatesMutex.Lock() // Lock again ONLY to update attempt count/time
				for _, fqdn := range domainsToRetry {
					status, exists := domainStates[fqdn] // Get pointer, check existence
					if !exists || status.Responded || status.AttemptsMade >= config.Retries {
						continue // Status changed, or domain removed? Skip retry.
					}

					pktInfo, err := prepareSinglePacket(fqdn, srcIPRetry, srcMACRetry, dstMACRetry, config.Nameservers, rngRetry)
					if err != nil {
						log.Printf("Error preparing retry packet for %s: %v. Marking failed.", fqdn, err)
						status.AttemptsMade = config.Retries
						failCount++ // Adjust counts
					} else {
						pktInfo.Attempt = status.AttemptsMade + 1
						// Non-blocking send to queue, might drop if full but unlikely
						select {
						case packetQueue <- pktInfo:
							queuedRetries++
							status.AttemptsMade++
							status.LastAttempt = time.Now()
							retryPendCount++ // It's now pending retry completion
							if config.Verbose {
								log.Printf("Retrying domain %s (Attempt %d)", fqdn, status.AttemptsMade)
							}
						default:
							//log.Printf("Warning: Packet queue full when trying to retry %s", fqdn)
							// Don't increment attempts if queue fails, it will retry check next tick
						}
					}
				}
				domainStatesMutex.Unlock() // Unlock after updating attempts
				if config.Verbose && queuedRetries > 0 {
					log.Printf("Queued %d retries.", queuedRetries)
				}
			}

			// --- Update Stats ---
			// Get current raw XDP stats... (your existing code)
			curRawStats, _ := xsk.Stats()
			intervalPacketsRaw := curRawStats.Completed - lastRawStats.Completed
			intervalSeconds := 500.0 / 1000.0 // Approx.
			intervalRateRaw := uint64(float64(intervalPacketsRaw) / intervalSeconds)
			avgRateRaw := 0.0
			if duration > 0 {
				avgRateRaw = float64(curRawStats.Completed) / duration
			}
			lastRawStats = curRawStats

			currentReceived := atomic.LoadUint64(&receivedPackets)

			// Send update to statsCollector (use counts calculated above)
			updateData := StatsUpdateData{
				TotalDomains:        totalDoms,
				RespondedDomains:    respCount,      // Now reflects cache checks
				RetryingDomains:     retryPendCount, // Updated count
				FailedDomains:       failCount,      // May increase due to retries
				ReceivedPackets:     currentReceived,
				PacketsSentRaw:      curRawStats.Completed,
				PacketsPerSecRaw:    intervalRateRaw,
				AvgPacketsPerSecRaw: avgRateRaw,
				Duration:            duration,
			}

			select {
			case statsUpdateChan <- updateData:
			default:
				// Stats channel full
			}

			// --- Check for Completion (using updated respCount, failCount) ---
			// Add verbose logging here to see the counts
			if config.Verbose && (respCount > 0 || failCount > 0) {
				log.Printf("Loop Check: Responded=%d, Failed=%d, Total=%d", respCount, failCount, totalDoms)
			}
			if respCount+failCount == totalDoms {
				log.Printf("Termination condition met: Responded=%d, Failed=%d, Total=%d", respCount, failCount, totalDoms)
				break loop // <<< THIS SHOULD NOW BE REACHED
			}

		case <-timeout:
			log.Println("Maximum runtime reached.")
			break loop // Exit loop on global timeout
		}
	}
	// --- Shutdown ---
	log.Println("Stopping packet sender...")
	close(stopSender) // Signal sender to stop
	senderWg.Wait()   // Wait for sender to finish finalizing and exit

	log.Println("Stopping statistics collector...")
	close(stopStats) // Signal stats collector to stop
	<-programDone    // Wait for stats/UI to finish

	// --- Final Report ---
	finalResponded := 0
	finalFailed := 0
	failedDomainsList := []string{}
	domainStatesMutex.Lock()
	for fqdn, status := range domainStates {
		// Final check against cache in case responses came late
		if !status.Responded {
			if _, found := cache.Get(fqdn); found {
				status.Responded = true
			}
		}
		if status.Responded {
			finalResponded++
		} else {
			finalFailed++
			if len(failedDomainsList) < 20 { // Limit printing
				failedDomainsList = append(failedDomainsList, fqdn)
			}
		}
	}
	domainStatesMutex.Unlock()

	fmt.Printf("\n--- Final Summary ---")
	fmt.Printf("\nTotal Domains: %d", totalDomains)
	fmt.Printf("\nResponded:     %d", finalResponded)
	fmt.Printf("\nFailed:        %d", finalFailed)
	fmt.Printf("\nTotal Runtime: %.2f seconds", time.Since(startTime).Seconds())
	if finalFailed > 0 {
		fmt.Println("\nDomains without responses:")
		for _, domain := range failedDomainsList {
			fmt.Printf("- %s\n", domain)
		}
		if finalFailed > len(failedDomainsList) {
			fmt.Printf("- ... (and %d more)\n", finalFailed-len(failedDomainsList))
		}
	}
	fmt.Println("---------------------")

	return nil // Indicate success
}

// Helper to prepare a single packet (extracted from original preparePackets)
func prepareSinglePacket(fqdn string, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, nameservers []string, rng *rand.Rand) (PacketInfo, error) {
	if len(nameservers) == 0 {
		return PacketInfo{}, fmt.Errorf("no nameservers available for %s", fqdn)
	}
	currentNameserver := nameservers[rng.Intn(len(nameservers))]
	dstIP := net.ParseIP(currentNameserver)
	if dstIP == nil {
		return PacketInfo{}, fmt.Errorf("invalid nameserver IP %s for %s", currentNameserver, fqdn)
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: 0, Protocol: layers.IPProtocolUDP,
		SrcIP: srcIP, DstIP: dstIP,
	}
	udp := &layers.UDP{SrcPort: layers.UDPPort(1024 + rng.Intn(65535-1024)), DstPort: 53} // Random source port
	udp.SetNetworkLayerForChecksum(ip)

	query := new(dns.Msg)
	query.SetQuestion(fqdn, dns.TypeA) // Already FQDN
	dnsPayload, err := query.Pack()
	if err != nil {
		return PacketInfo{}, fmt.Errorf("packing DNS query for %s: %w", fqdn, err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(dnsPayload))
	if err != nil {
		return PacketInfo{}, fmt.Errorf("serializing layers for %s: %w", fqdn, err)
	}

	return PacketInfo{Domain: fqdn, PacketBytes: buf.Bytes()}, nil
}

type StatsUpdateData struct { // Define a struct for stats data
	TotalDomains     int
	RespondedDomains int
	RetryingDomains  int
	FailedDomains    int
	ReceivedPackets  uint64
	// Add raw XDP stats if manager calculates them, or calculate here
	PacketsSentRaw      uint64
	PacketsPerSecRaw    uint64
	AvgPacketsPerSecRaw float64
	Duration            float64
}

// --- Need to update statsCollector slightly ---
func statsCollector(xsk *xdp.Socket, updateChan <-chan StatsUpdateData, stopStats <-chan struct{}, programDone chan<- struct{}, config *Config) {
	var p *tea.Program

	// --- UI Initialization (remains similar) ---
	if !config.TextOutput {
		// Initialize Bubble Tea Program 'p'
		// ... (same as before) ...
		// Start p.Run() in a goroutine
		// ... (same as before) ...
	} else {
		// Print header for text mode
		// ... (same as before) ...
	}

	ticker := time.NewTicker(1 * time.Second) // For periodic raw stats polling
	defer ticker.Stop()

	for {
		select {
		case updateData, ok := <-updateChan: // Receive data from manager
			if !ok {
				// Channel closed by manager, ignore further updates? Or handle final state?
				// Assume manager sends final update before closing.
				continue
			}

			// Now we have the latest domain counts and duration from the manager
			if !config.TextOutput && p != nil {
				p.Send(statsUpdateMsg{ // Map received data to UI message
					totalDomains:        updateData.TotalDomains,
					respondedDomains:    updateData.RespondedDomains,
					retryingDomains:     updateData.RetryingDomains,
					failedDomains:       updateData.FailedDomains,
					packetsSentRaw:      updateData.PacketsSentRaw,      // Use data from manager
					packetsPerSecRaw:    updateData.PacketsPerSecRaw,    // Use data from manager
					avgPacketsPerSecRaw: updateData.AvgPacketsPerSecRaw, // Use data from manager
					receivedPackets:     updateData.ReceivedPackets,
					duration:            updateData.Duration,
				})
			} else if config.TextOutput {
				// Print text stats using updateData
				prog := 0.0
				if updateData.TotalDomains > 0 {
					prog = float64(updateData.RespondedDomains+updateData.FailedDomains) / float64(updateData.TotalDomains) * 100
				}
				fmt.Printf("\rD: %d| Rsp: %d| Fail: %d| Rx: %d| RawTX: %d| RawRate: %d pps| RawAvg: %.1f pps| Time: %.1fs | Prog: %.1f%% ",
					updateData.TotalDomains, updateData.RespondedDomains, updateData.FailedDomains, updateData.ReceivedPackets,
					updateData.PacketsSentRaw, updateData.PacketsPerSecRaw, updateData.AvgPacketsPerSecRaw, updateData.Duration, prog)
			}

		case <-ticker.C:
			// Periodically get raw XDP stats *here* if needed for rate calculation

			// Calculate raw interval rate

			// If the manager isn't sending raw stats, update the UI/text here
			// This might lead to slight discrepancies if updateChan message arrives later
			// It's generally better if the manager sends the complete snapshot.
			// Let's assume the manager sends everything in `updateData`.

		case <-stopStats:
			log.Println("Stats collector received stop signal.")
			// Handle final UI update or text printing (maybe receive one last updateData?)
			// ... (similar finalization logic as before) ...
			if !config.TextOutput && p != nil {
				// Optionally wait for a final update message or use last known state
				time.Sleep(150 * time.Millisecond) // Give UI time
				p.Quit()
			} else if config.TextOutput {
				fmt.Println("\n--- Final Stats ---") // Print final summary
				// Use last received updateData or fetch final counts
				programDone <- struct{}{}
			}
			log.Println("Stats collector finished.")
			return
		}
	}
}

// finalizeTransmission ensures all packets are properly transmitted
func finalizeTransmission(xsk *xdp.Socket) {
	if globalConfig.Verbose {
		log.Println("Starting transmission finalization...")
	}
	// Give potentially inflight packets a very brief moment
	// time.Sleep(5 * time.Millisecond) // Reduced sleep

	startTime := time.Now()
	timeout := 500 * time.Millisecond // Max time to wait for final completions

	// Process any remaining completions aggressively
	for time.Since(startTime) < timeout {
		numTransmitting := xsk.NumTransmitted()
		if numTransmitting == 0 {
			if globalConfig.Verbose {
				log.Printf("Finalization: No more packets tracked as transmitting.")
			}
			break // Exit loop if TX queue seems empty
		}

		if globalConfig.Verbose {
			log.Printf("Finalization: Waiting for %d packets to complete transmission...", numTransmitting)
		}

		// Poll briefly and process completions
		// Use a shorter timeout (e.g., 10ms)
		_, _, err := xsk.Poll(10) // MODIFIED: Reduced poll timeout
		if err != nil && err != unix.ETIMEDOUT && err != unix.EINTR {
			log.Printf("Final poll error: %v", err)
			// Don't break necessarily, try completing anyway
		}

		completed := xsk.NumCompleted()
		if completed > 0 {
			xsk.Complete(completed)
			if globalConfig.Verbose {
				log.Printf("Finalization: Completed %d packets", completed)
			}
		} else if err == unix.ETIMEDOUT {
			// If poll timed out and nothing completed, yield and retry poll
			runtime.Gosched()
		}
	}

	finalNumTransmitting := xsk.NumTransmitted()
	if finalNumTransmitting > 0 {
		log.Printf("Warning: Finalization finished, but %d packets still marked as transmitting.", finalNumTransmitting)
	} else if globalConfig.Verbose {
		log.Println("Finalization complete.")
	}
}

func AppendToFile(resultsArray *dns.Msg, outputFile string) {

	json, err := json.Marshal(resultsArray)
	if err != nil {
		log.Printf("Error marshalling results: %v", err)
	}
	// append to file
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Error opening file: %v", err)
	}
	defer file.Close()
	file.Write(json)
	file.Write([]byte("\n"))
}

// Custom structure for improved JSON output
type PrettyDnsFlags struct {
	Authoritative      bool `json:"Authoritative"`
	Truncated          bool `json:"Truncated"`
	RecursionDesired   bool `json:"RecursionDesired"`
	RecursionAvailable bool `json:"RecursionAvailable"`
	AuthenticatedData  bool `json:"AuthenticatedData"`
	CheckingDisabled   bool `json:"CheckingDisabled"`
}

type PrettyDnsQuestion struct {
	Name  string `json:"Name"`
	Type  string `json:"Type"`
	Class string `json:"Class"`
}

type PrettyDnsAnswer struct {
	Name  string `json:"Name"`
	Type  string `json:"Type"`
	Class string `json:"Class"`
	TTL   uint32 `json:"TTL"`
	Data  string `json:"Data"` // Simplified: Assumes data can be stringified
}

type PrettyDnsMsg struct {
	TransactionID uint16              `json:"TransactionID"`
	MessageType   string              `json:"MessageType"`
	Opcode        string              `json:"Opcode"`
	ResponseCode  string              `json:"ResponseCode"`
	Flags         PrettyDnsFlags      `json:"Flags"`
	Question      []PrettyDnsQuestion `json:"Question"`
	Answers       []PrettyDnsAnswer   `json:"Answers"`
	Authority     []PrettyDnsAnswer   `json:"Authority"`  // Using same struct for simplicity
	Additional    []PrettyDnsAnswer   `json:"Additional"` // Using same struct for simplicity
}

// Function to convert dns.Msg to PrettyDnsMsg
func prettifyDnsMsg(msg *dns.Msg) *PrettyDnsMsg {
	if msg == nil {
		return nil
	}

	pretty := &PrettyDnsMsg{
		TransactionID: msg.Id,
		MessageType:   "Query", // Default
		Opcode:        dns.OpcodeToString[msg.Opcode],
		ResponseCode:  dns.RcodeToString[msg.Rcode],
		Flags: PrettyDnsFlags{
			Authoritative:      msg.Authoritative,
			Truncated:          msg.Truncated,
			RecursionDesired:   msg.RecursionDesired,
			RecursionAvailable: msg.RecursionAvailable,
			AuthenticatedData:  msg.AuthenticatedData,
			CheckingDisabled:   msg.CheckingDisabled,
		},
		Question:   make([]PrettyDnsQuestion, len(msg.Question)),
		Answers:    make([]PrettyDnsAnswer, len(msg.Answer)),
		Authority:  make([]PrettyDnsAnswer, len(msg.Ns)),
		Additional: make([]PrettyDnsAnswer, len(msg.Extra)),
	}

	if msg.Response {
		pretty.MessageType = "Response"
	}

	for i, q := range msg.Question {
		pretty.Question[i] = PrettyDnsQuestion{
			Name:  q.Name,
			Type:  dns.TypeToString[q.Qtype],
			Class: dns.ClassToString[q.Qclass],
		}
	}

	mapRR := func(rr dns.RR) PrettyDnsAnswer {
		hdr := rr.Header()
		// This is a simplification; real implementation needs type assertion
		// to get the specific data (A, CNAME, MX, etc.) correctly stringified.
		data := rr.String() // Fallback using String() method
		// A more robust way extracts specific fields:
		if a, ok := rr.(*dns.A); ok {
			data = a.A.String()
		} else if cname, ok := rr.(*dns.CNAME); ok {
			data = cname.Target
		} // ... add other types as needed

		// Example: Trim header part from default String() output if used as fallback
		// data = strings.TrimPrefix(data, hdr.String())

		return PrettyDnsAnswer{
			Name:  hdr.Name,
			Type:  dns.TypeToString[hdr.Rrtype],
			Class: dns.ClassToString[hdr.Class],
			TTL:   hdr.Ttl,
			Data:  data, // Placeholder - needs proper extraction based on RR type
		}
	}

	for i, rr := range msg.Answer {
		pretty.Answers[i] = mapRR(rr)
	}
	for i, rr := range msg.Ns {
		pretty.Authority[i] = mapRR(rr)
	}
	for i, rr := range msg.Extra {
		// Handle OPT Pseudo-RR type specifically if needed, otherwise map like others
		if _, ok := rr.(*dns.OPT); ok {
			// Decide how to represent OPT record, maybe skip or add specific fields
			// For now, just skipping it in this example
			pretty.Additional = pretty.Additional[:i] // Quick way to shrink if skipping
			continue                                  // Skip OPT records in this simple example
		}
		pretty.Additional[i] = mapRR(rr)
	}

	return pretty
}

func saveCachePrettified(filename string) { // Replace YourCacheType
	outFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating file %s: %v", filename, err)
	}
	defer outFile.Close()

	savedCount := 0
	// Assuming cache.ForEach iterates through *dns.Msg values
	cache.ForEach(func(domainKey string, responseMsg *dns.Msg) bool {
		if responseMsg != nil {
			prettyMsg := prettifyDnsMsg(responseMsg)
			if prettyMsg == nil {
				return true // Should not happen if responseMsg != nil, but safe check
			}

			// Use MarshalIndent for pretty printing
			jsonData, err := json.MarshalIndent(prettyMsg, "", "  ") // Indent with 2 spaces
			if err != nil {
				log.Printf("Error marshalling pretty result for %s: %v", domainKey, err)
				return true // Continue ForEach
			}
			_, err = outFile.Write(jsonData)
			if err == nil {
				_, err = outFile.Write([]byte("\n")) // Add newline separator
			}
			if err != nil {
				log.Printf("Error writing pretty result for %s to file: %v", domainKey, err)
				// Potentially stop or just log
			} else {
				savedCount++
			}
		}
		return true // Continue iterating
	})
	log.Printf("Saved %d prettified records to %s", savedCount, filename)
}

func main() {
	// Initialize configuration
	config := DefaultConfig()

	// Parse command line flags
	domainsFile := flag.String("domains", "", "File containing domains to query (one per line)")
	nameserversFile := flag.String("nameservers", "", "File containing nameservers to use (one per line)")

	flag.StringVar(&config.NIC, "interface", config.NIC, "Network interface to attach to")
	flag.IntVar(&config.QueueID, "queue", config.QueueID, "The queue on the network interface to attach to")
	flag.StringVar(&config.SrcMAC, "srcmac", config.SrcMAC, "Source MAC address (optional, uses interface MAC if empty)")
	flag.StringVar(&config.DstMAC, "dstmac", config.DstMAC, "Destination MAC address (optional, uses ARP resolution if empty)")
	flag.StringVar(&config.SrcIP, "srcip", config.SrcIP, "Source IP address (optional, uses interface IP if empty)")
	flag.StringVar(&config.DomainName, "domain", config.DomainName, "Single domain to query (when not using -domains file)")
	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "Enable verbose output")
	flag.BoolVar(&config.TextOutput, "text", config.TextOutput, "Use simple text output instead of interactive UI")
	flag.IntVar(&config.PollTimeoutMs, "poll", config.PollTimeoutMs, "Poll timeout in milliseconds")
	flag.IntVar(&config.NumWorkers, "workers", config.NumWorkers, "Number of workers to use")
	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "File to save results to")
	flag.IntVar(&config.Retries, "retries", config.Retries, "Number of retries for each domain")
	flag.Parse()

	// Validate required parameters
	if config.NIC == "" {
		log.Fatal("Error: interface (-interface) is required")
	}

	// Initialize the interface
	link, err := netlink.LinkByName(config.NIC)
	if err != nil {
		log.Fatalf("Error: couldn't find interface %s: %v", config.NIC, err)
	}
	// Use interface address if source IP not specified
	if config.SrcIP == "" {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			log.Fatalf("Error: failed to get interface addresses: %v", err)
		}
		if len(addrs) == 0 {
			log.Fatal("Error: no IPv4 addresses configured on interface")
		}
		config.SrcIP = addrs[0].IP.String()
		fmt.Printf("Using interface IP address: %s\n", config.SrcIP)
	}
	// Start BPF receiver and wait for it to be ready
	bpfExited := make(chan struct{}) // To know when BPF receiver exits fully
	go func() {
		BpfReceiver(config)
		close(bpfExited)
	}()
	<-startedBPF // Wait for BPF to signal it's ready

	globalConfig = config // Set global config
	// Load domains from file if specified
	domains := []string{config.DomainName}
	if *domainsFile != "" {
		loadedDomains, err := readDomainsFromFile(*domainsFile)
		if err != nil {
			log.Fatalf("Error reading domains file: %v", err)
		}
		if len(loadedDomains) > 0 {
			domains = loadedDomains
			fmt.Printf("Loaded %d domains from %s\n", len(domains), *domainsFile)
		} else {
			log.Fatalf("Error: no domains found in %s", *domainsFile)
		}
	}

	// Load nameservers from file if specified
	if *nameserversFile != "" {
		nameservers, err := readDomainsFromFile(*nameserversFile)
		if err != nil {
			log.Fatalf("Error reading nameservers file: %v", err)
		}
		if len(nameservers) > 0 {
			config.Nameservers = nameservers
			fmt.Printf("Loaded %d nameservers from %s\n", len(nameservers), *nameserversFile)
		}
	}

	if len(config.Nameservers) == 0 {
		log.Fatal("Error: no nameservers provided")
	}

	opts := &xdp.SocketOptions{
		NumFrames:              2048, // Increase UMEM frames
		FrameSize:              2048, // Standard MTU size
		FillRingNumDescs:       512,  // Increase ring sizes
		CompletionRingNumDescs: 512,
		RxRingNumDescs:         16, // Minimal RX needed by XDP socket itself
		TxRingNumDescs:         512,
		// Flags:                  xdp.XdpFlagsNeedWakeup, // Might help if sender often waits
	}

	// Initialize XDP socket
	xsk, err := xdp.NewSocket(link.Attrs().Index, config.QueueID, opts)
	if err != nil {
		log.Fatalf("Error creating XDP socket: %v", err)
	}
	defer xsk.Close() // Ensure socket is closed eventually

	log.Println("Starting transmission process...")
	// Call the refactored manager function
	err = transmitPackets(xsk, domains, config)
	if err != nil {
		log.Fatalf("Transmission process failed: %v", err)
	}

	log.Println("Transmission process finished.")
	// Final saving logic (can be refined)
	log.Println("Saving results from cache to file:", config.OutputFile)
	saveCachePrettified(config.OutputFile)

	log.Println("Signaling BPF receiver to stop...")
	close(stopper) // Signal BPF receiver via global stopper
	<-bpfExited    // Wait for BPF receiver to fully exit

	log.Println("Program finished.")

}
