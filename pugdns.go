/*
pugdns: a fast DNS bruteforcer
*/
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"

	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/rand"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

// --- Data Structures ---

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

// StatsUpdateData struct used to pass data to the statsCollector
type StatsUpdateData struct {
	TotalDomains        int
	RespondedDomains    int
	RetryingDomains     int // Domains attempted but not yet responded/failed/timedout
	FailedDomains       int
	ReceivedPackets     uint64
	PacketsSentRaw      uint64 // Based on XDP Completed stats
	PacketsPerSecRaw    uint64
	AvgPacketsPerSecRaw float64
	Duration            float64
}

// --- Global Variables (Minimized) ---

// Global counters accessed concurrently
var receivedPackets uint64          // Updated by BPF receiver
var statsPacketSentAttempted uint64 // Updated by Sender before submit

// --- Utility Functions ---

// readDomainsFromFile reads items (domains/nameservers) from a file, one per line
func readDomainsFromFile(filename string) ([]string, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	items := []string{}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file '%s': %w", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") { // Ignore empty lines and comments
			items = append(items, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file '%s': %w", filename, err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("no valid items found in file '%s'", filename)
	}

	return items, nil
}

// --- Packet Preparation ---

// prepareSinglePacket creates the raw bytes for a single DNS query packet.
func prepareSinglePacket(fqdn string, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, config *Config, rng *rand.Rand) (PacketInfo, error) {
	if len(config.Nameservers) == 0 {
		return PacketInfo{}, fmt.Errorf("no nameservers configured for %s", fqdn)
	}
	// Select random nameserver for this packet
	currentNameserver := config.Nameservers[rng.Intn(len(config.Nameservers))]
	dstIP := net.ParseIP(currentNameserver)
	if dstIP == nil {
		return PacketInfo{}, fmt.Errorf("invalid nameserver IP %s for %s", currentNameserver, fqdn)
	}
	dstIP = dstIP.To4() // Ensure IPv4
	if dstIP == nil {
		return PacketInfo{}, fmt.Errorf("nameserver IP %s is not a valid IPv4 address for %s", currentNameserver, fqdn)
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: uint16(rng.Intn(65535)), Protocol: layers.IPProtocolUDP, // Random IP ID
		SrcIP: srcIP, DstIP: dstIP, Flags: layers.IPv4DontFragment, // Added Don't Fragment flag
	}
	// Choose a random source port for UDP
	srcPort := layers.UDPPort(1024 + rng.Intn(65535-1024))
	udp := &layers.UDP{SrcPort: srcPort, DstPort: 53} // Standard DNS port 53
	udp.SetNetworkLayerForChecksum(ip)                // Important for checksum calculation

	// Create DNS query message
	query := new(dns.Msg)
	query.Id = uint16(rng.Intn(65535)) // Random DNS transaction ID
	query.RecursionDesired = true      // Set RD bit for recursive query
	query.Question = []dns.Question{{
		Name:   fqdn,          // Fully qualified domain name
		Qtype:  dns.TypeA,     // Query for A records (IPv4 addresses)
		Qclass: dns.ClassINET, // Internet class
	}}
	query.SetEdns0(4096, false) // Add EDNS0 OPT record

	// Pack the DNS message into wire format
	dnsPayload, err := query.Pack()
	if err != nil {
		return PacketInfo{}, fmt.Errorf("packing DNS query for %s: %w", fqdn, err)
	}

	// Serialize all layers into a byte buffer
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true} // Automatically fix lengths and compute checksums
	err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(dnsPayload))
	if err != nil {
		return PacketInfo{}, fmt.Errorf("serializing layers for %s: %w", fqdn, err)
	}

	return PacketInfo{Domain: fqdn, PacketBytes: buf.Bytes()}, nil
}

// --- XDP Packet Sending ---

// packetSender is a goroutine dedicated to sending packets via XDP socket.
func packetSender(ctx context.Context, xsk *xdp.Socket, packetQueue <-chan PacketInfo, limiter *rate.Limiter, wg *sync.WaitGroup, config *Config, domainStates map[string]*DomainStatus,
	domainStatesMutex *sync.Mutex) {
	defer wg.Done()
	log.Println("Packet sender started.")

	maxBatchSize := config.MaxBatchSize
	pollTimeout := config.PollTimeoutMs

	for {
		// 1. Handle Completions first (non-blocking poll)
		_, _, pollErr := xsk.Poll(0) // Non-blocking poll
		if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR && pollErr != unix.EAGAIN {
			log.Printf("Sender Poll error: %v", pollErr)
		} else {
			numCompleted := xsk.NumCompleted()
			if numCompleted > 0 {
				xsk.Complete(numCompleted)
			}
		}

		// 2. Check for stop signal (via context cancellation)
		select {
		case <-ctx.Done():
			log.Println("Packet sender received stop signal via context. Finalizing...")
			finalizeTransmission(xsk, config)
			log.Println("Packet sender finished.")
			return
		default:
			// Continue if context is not cancelled
		}

		// 3. Get Available Descriptors
		freeSlots := xsk.NumFreeTxSlots()
		if freeSlots == 0 {
			// Try polling with timeout if no slots initially
			_, _, pollErr = xsk.Poll(pollTimeout)
			if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR {
				log.Printf("Sender Poll(timeout) error: %v", pollErr)
			}
			numCompleted := xsk.NumCompleted()
			if numCompleted > 0 {
				xsk.Complete(numCompleted)
			}
			freeSlots = xsk.NumFreeTxSlots() // Check again
			if freeSlots == 0 {
				runtime.Gosched() // Yield if still no slots
				continue
			}
		}

		descsToRequest := freeSlots
		if descsToRequest > maxBatchSize {
			descsToRequest = maxBatchSize
		}
		if descsToRequest == 0 { // Should theoretically not happen if freeSlots > 0
			runtime.Gosched()
			continue
		}

		// Use the original GetDescs method
		descs := xsk.GetDescs(descsToRequest, false) // Don't wait
		if len(descs) == 0 {
			// Didn't get any descriptors, maybe completions happened just now
			runtime.Gosched()
			continue
		}

		// 4. Fill Descriptors from Queue (Non-blocking)
		packetsToSend := make([]PacketInfo, 0, len(descs))
		descsFilled := 0

	fillLoop:
		for i := 0; i < len(descs); i++ {
			select {
			case pktInfo, ok := <-packetQueue:
				if !ok {
					// Channel closed, manager wants to stop. Stop filling.
					log.Println("Packet queue closed. Sender stopping fill loop.")
					// Unused descriptors obtained in 'descs' will be implicitly handled
					// by the XDP ring logic or the next call to GetDescs.
					break fillLoop // Exit fill loop, proceed to transmit what we have
				}
				if len(pktInfo.PacketBytes) == 0 {
					log.Printf("Warning: Empty packet bytes for domain %s", pktInfo.Domain)
					continue // Skip this packet, don't use a descriptor from 'descs'
				}
				// Use descs[descsFilled] because we are filling sequentially
				frame := xsk.GetFrame(descs[descsFilled])
				if len(frame) < len(pktInfo.PacketBytes) {
					log.Printf("Error: Frame size (%d) too small for packet (%d bytes) for domain %s. Skipping.", len(frame), len(pktInfo.PacketBytes), pktInfo.Domain)
					// This descriptor descs[descsFilled] remains unused in this batch
					continue // Skip this packet
				}

				// Copy data and update length for the descriptor we are using
				frameLen := copy(frame, pktInfo.PacketBytes)
				descs[descsFilled].Len = uint32(frameLen)

				packetsToSend = append(packetsToSend, pktInfo) // Track successfully prepared packet
				descsFilled++                                  // Increment count of successfully filled descriptors

			default:
				// Queue is empty, stop filling descriptors for this batch
				break fillLoop
			}
		}

		// 5. Apply Rate Limiting and Transmit the Batch
		if descsFilled > 0 {

			// Wait until the rate limiter allows sending this many packets.
			err := limiter.WaitN(ctx, descsFilled)

			if err != nil {
				// Error likely means context was canceled (shutdown signal)
				log.Printf("Rate limiter wait error: %v. Sender stopping transmission.", err)
				// Don't finalize here, let the main context check handle it
				break // Exit the main for loop
			}

			// --- >>> NEW: Update LastAttempt before transmitting <<< ---
			now := time.Now() // Get time once for the batch about to be sent
			domainStatesMutex.Lock()
			maxRetries := config.Retries + 1        // Calculate once
			for _, pktInfo := range packetsToSend { // packetsToSend only contains successfully prepared packets for this batch
				if status, ok := domainStates[pktInfo.Domain]; ok {
					// Only update if the domain is still actively being attempted
					// (Handles cases where it might have been marked responded/failed between queuing and sending)
					if !status.Responded && status.AttemptsMade < maxRetries {
						// Note: AttemptsMade was incremented when this packet was queued.
						// We are now setting the timestamp for *that* attempt.
						status.LastAttempt = now
					}
				} else {
					// This might happen if domain was removed or map cleared, though unlikely in this flow
					log.Printf("Warning: Domain %s not found in states map during sender timestamping.", pktInfo.Domain)
				}
			}
			domainStatesMutex.Unlock()
			// --- >>> End timestamp update <<< --
			// Proceed with transmission after waiting. Transmit only the filled descriptors.
			numSubmitted := xsk.Transmit(descs[:descsFilled]) // Use the slice of filled descriptors
			atomic.AddUint64(&statsPacketSentAttempted, uint64(descsFilled))

			if numSubmitted < descsFilled {
				log.Printf("Warning: Sender failed to submit %d packets (%d/%d). Manager will retry.", descsFilled-numSubmitted, numSubmitted, descsFilled)
			}
		} else {
			// No packets were dequeued and prepared in this iteration.
			// We might have obtained descriptors in 'descs' but didn't use them.
			// The XDP library/ring mechanism handles reuse/release implicitly.
			// Yield briefly to avoid busy loop if queue stays empty.
			runtime.Gosched()
		}

		// Check context again at the end of the loop iteration for faster exit
		select {
		case <-ctx.Done():
			break // Exit the main for loop
		default:
			// Continue
		}

	} // End main for loop

	// Finalization is handled by the deferred wg.Done() and the context check/return path
	// If loop exited NOT via the explicit return path after context check, finalize might be needed?
	// The explicit return path *does* call finalize. If the loop breaks due to limiter error,
	// the caller (`transmitPackets`) should handle the shutdown sequence including waiting
	// for this goroutine via wg.Wait() which ensures wg.Done() runs.
	// The finalize in the explicit ctx.Done() path seems sufficient.
	// Let's remove the potentially redundant finalize call here.
	// if ctx.Err() == nil { // Avoid double finalize
	//     log.Println("Packet sender loop finished unexpectedly. Finalizing...")
	//     finalizeTransmission(xsk, config)
	//     log.Println("Packet sender finished.")
	// }
}

// finalizeTransmission tries to ensure all packets in flight are sent before shutdown.
func finalizeTransmission(xsk *xdp.Socket, config *Config) {
	if config.Verbose {
		log.Println("Starting transmission finalization...")
	}
	startTime := time.Now()
	timeout := 1000 * time.Millisecond // Increased timeout slightly

	for time.Since(startTime) < timeout {
		numTransmitting := xsk.NumTransmitted()
		if numTransmitting == 0 {
			if config.Verbose {
				log.Printf("Finalization: No packets transmitting after %.2fs.", time.Since(startTime).Seconds())
			}
			break
		}

		// Poll briefly for completions
		_, _, pollErr := xsk.Poll(20) // Short poll timeout
		if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR {
			log.Printf("Final poll error: %v", pollErr)
		}

		completed := xsk.NumCompleted()
		if completed > 0 {
			xsk.Complete(completed)
			if config.Verbose {
				log.Printf("Finalization: Completed %d packets", completed)
			}
			// Optional: Reset timer slightly if progress is made?
			// startTime = time.Now()
		} else if pollErr == unix.ETIMEDOUT || pollErr == unix.EINTR || pollErr == nil {
			runtime.Gosched() // Yield if no completions or expected interruptions
		} else {
			break // Break on unexpected poll errors
		}
	}

	finalNumTransmitting := xsk.NumTransmitted()
	if finalNumTransmitting > 0 {
		log.Printf("Warning: Finalization finished, but %d packets still marked as transmitting.", finalNumTransmitting)
	} else if config.Verbose {
		log.Println("Finalization complete.")
	}
}

// --- Statistics ---

// statsCollector receives stats updates and logs them.
func statsCollector(updateChan <-chan StatsUpdateData, stopStats <-chan struct{}, programDone chan<- struct{}, config *Config) {
	log.Println("Statistics collector started.")
	var lastUpdate StatsUpdateData
	ticker := time.NewTicker(500 * time.Millisecond) // Update frequency for logging
	defer ticker.Stop()
	running := true

	for running {
		select {
		case updateData, ok := <-updateChan:
			if !ok {
				running = false // Channel closed, prepare to exit loop
				break
			}
			lastUpdate = updateData // Store latest data

		case <-ticker.C:
			if lastUpdate.TotalDomains > 0 { // Only print if we have data
				prog := 0.0
				// Progress represents completed domains (responded or failed)
				prog = float64(lastUpdate.RespondedDomains+lastUpdate.FailedDomains) / float64(lastUpdate.TotalDomains) * 100

				// Log stats using log.Printf with carriage return (\r) to overwrite the line
				// Note: RawTX is based on XDP Completed packets count
				log.Printf("\rD:%d | Rsp:%d | Fail:%d | Pend:%d | Rx:%d | RawTX:%d | RawRate:%d pps | RawAvg:%.1f pps | Time:%.1fs | Prog:%.1f%% ",
					lastUpdate.TotalDomains, lastUpdate.RespondedDomains, lastUpdate.FailedDomains, lastUpdate.RetryingDomains,
					lastUpdate.ReceivedPackets, lastUpdate.PacketsSentRaw, lastUpdate.PacketsPerSecRaw,
					lastUpdate.AvgPacketsPerSecRaw, lastUpdate.Duration, prog)
			}

		case <-stopStats:
			running = false // Signal received, prepare to exit loop
			break
		}
	}

	// Cleanup after loop exit
	fmt.Println() // Print a newline to move cursor off the constantly updating stats line
	log.Println("Statistics collector shutting down.")

	// Log final stats if available
	if lastUpdate.TotalDomains > 0 {
		prog := float64(lastUpdate.RespondedDomains+lastUpdate.FailedDomains) / float64(lastUpdate.TotalDomains) * 100
		log.Printf("Final Stats: D:%d | Rsp:%d | Fail:%d | Pend:%d | Rx:%d | RawTX:%d | RawRate:%d pps | RawAvg:%.1f pps | Time:%.1fs | Prog:%.1f%% ",
			lastUpdate.TotalDomains, lastUpdate.RespondedDomains, lastUpdate.FailedDomains, lastUpdate.RetryingDomains,
			lastUpdate.ReceivedPackets, lastUpdate.PacketsSentRaw, lastUpdate.PacketsPerSecRaw,
			lastUpdate.AvgPacketsPerSecRaw, lastUpdate.Duration, prog)
	}
	programDone <- struct{}{} // Signal that cleanup is done
}

// --- State Management and Orchestration ---

// queueInitialDomains prepares and queues the initial set of domains.
func queueInitialDomains(initialDomains []string, packetQueue chan<- PacketInfo, domainStates map[string]*DomainStatus, domainStatesMutex *sync.Mutex, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, config *Config, rng *rand.Rand) int {
	log.Printf("Preparing and queuing initial %d domains...", len(initialDomains))
	initialPacketsPrepared := 0

	// No need to lock the mutex here, as domainStates is populated before this call
	// and we only read from initialDomains. We'll lock inside the loop only on success.

	for _, fqdn := range initialDomains {
		pktInfo, err := prepareSinglePacket(fqdn, srcIP, srcMAC, dstMAC, config, rng)
		if err != nil {
			log.Printf("Error preparing initial packet for %s: %v. Will not be attempted initially.", fqdn, err)
			// DO NOT mark as failed here. Leave AttemptsMade at 0.
			// checkAndRetryDomains will pick it up later.
			continue
		}

		pktInfo.Attempt = 1 // This is the first attempt being queued
		select {
		case packetQueue <- pktInfo:
			initialPacketsPrepared++
			// Update status only on successful queueing
			domainStatesMutex.Lock()
			if status, ok := domainStates[fqdn]; ok {
				// Ensure it hasn't been marked responded by a race condition (unlikely here but safe)
				if !status.Responded {
					status.AttemptsMade = 1
					status.LastAttempt = time.Now() // Set time when queued
				}
			} else {
				// This should not happen if map is pre-populated correctly
				log.Printf("Error: Domain %s not found in states map during initial queue success.", fqdn)
			}
			domainStatesMutex.Unlock()
		default:
			log.Printf("Warning: Packet queue full during initial queuing for %s. Will be attempted later.", fqdn)
			// DO NOT update status. AttemptsMade remains 0.
		}
	}
	log.Printf("Queued %d initial packets.", initialPacketsPrepared)
	return initialPacketsPrepared
}

// checkAndRetryDomains checks domain status, looks for cache hits, and queues retries.
func checkAndRetryDomains(domainStates map[string]*DomainStatus, domainStatesMutex *sync.Mutex, packetQueue chan<- PacketInfo, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, config *Config, rng *rand.Rand) (respondedCount, failedCount, pendingCount int) {

	now := time.Now()
	domainsToTry := []string{} // Collect FQDNs needing a packet sent (initial or retry)

	maxRetries := config.Retries + 1 // Total attempts = 1 initial + config.Retries

	// --- Phase 1: Check status and identify candidates for sending ---
	domainStatesMutex.Lock()
	for fqdn, status := range domainStates {
		// Check cache first for any late responses
		// Assumes 'cache' is accessible (global from bpf.go)
		if !status.Responded { // Only check cache if not already marked responded
			if _, found := cache.Get(fqdn); found {
				if config.Verbose {
					log.Printf("Domain %s marked as responded based on cache check.", fqdn)
				}
				status.Responded = true
			}
		}

		if status.Responded {
			respondedCount++
			continue
		}

		// Check if failed (all attempts used up)
		if status.AttemptsMade >= maxRetries {
			failedCount++
			continue
		}

		// --- If not responded and not failed, check if needs attempt/retry ---
		needsAttempt := false
		if status.AttemptsMade == 0 {
			// Never successfully queued before
			needsAttempt = true
			if config.Verbose {
				// log.Printf("Domain %s needs initial attempt (AttemptsMade=0).", fqdn)
			}
		} else if !status.LastAttempt.IsZero() && now.Sub(status.LastAttempt) > config.RetryTimeout {
			// Attempted before, and timeout has expired since last attempt
			needsAttempt = true
			if config.Verbose {
				// log.Printf("Domain %s needs retry (timeout expired). Attempt %d", fqdn, status.AttemptsMade+1)
			}
		}

		if needsAttempt {
			domainsToTry = append(domainsToTry, fqdn)
		} else {
			// Still waiting for response/timeout from a previous attempt
			pendingCount++
		}
	}
	domainStatesMutex.Unlock() // Unlock after checking status and identifying candidates

	// --- Phase 2: Queue attempts/retries ---
	queuedCount := 0
	failedToPrepareCount := 0

	if len(domainsToTry) > 0 {
		if config.Verbose {
			log.Printf("Attempting to queue %d packets (initial/retry)...", len(domainsToTry))
		}
		for _, fqdn := range domainsToTry {
			// Lock *briefly* just to read the current attempt number needed
			var currentAttempt int
			domainStatesMutex.Lock()
			status, exists := domainStates[fqdn]
			// Re-check status in case it changed between Phase 1 and now (e.g., responded via cache)
			if !exists || status.Responded || status.AttemptsMade >= maxRetries {
				domainStatesMutex.Unlock()
				continue // Skip if state changed to responded/failed
			}
			currentAttempt = status.AttemptsMade // Use current value for packet prep
			domainStatesMutex.Unlock()

			// Prepare packet *outside* the main lock
			pktInfo, err := prepareSinglePacket(fqdn, srcIP, srcMAC, dstMAC, config, rng)
			if err != nil {
				log.Printf("Error preparing packet for %s (attempt %d): %v. Marking failed.", fqdn, currentAttempt+1, err)
				// Lock to mark as failed immediately if preparation fails
				domainStatesMutex.Lock()
				if status, ok := domainStates[fqdn]; ok {
					// Ensure it hasn't been responded/failed already by a race
					if !status.Responded && status.AttemptsMade < maxRetries {
						status.AttemptsMade = maxRetries // Mark as having used all retries
						// failedCount will be incremented in the next iteration's Phase 1
						failedToPrepareCount++
					}
				}
				domainStatesMutex.Unlock()
				continue // Skip trying to queue this one
			}

			pktInfo.Attempt = currentAttempt + 1 // Set attempt number for the packet itself

			// Try to queue the packet
			select {
			case packetQueue <- pktInfo:
				queuedCount++
				// Update status *after* successful queuing
				domainStatesMutex.Lock()
				// Re-fetch status and check again before updating
				status, exists := domainStates[fqdn]
				if exists && !status.Responded && status.AttemptsMade < maxRetries {
					// Only update if still relevant
					status.AttemptsMade++           // Increment attempt count
					status.LastAttempt = time.Now() // Update timestamp for next timeout check
				}
				domainStatesMutex.Unlock()
			default:
				// Failed to queue (queue full). Don't update attempts/time.
				// It will be picked up again in the next checkAndRetryDomains cycle.
				if config.Verbose {
					// log.Printf("Warning: Packet queue full when trying to queue %s (attempt %d). Will try again later.", fqdn, pktInfo.Attempt)
				}
				// Because we didn't update AttemptsMade/LastAttempt, it remains eligible for retry later.
				// We need to account for it in the pending count for this cycle.
				// Add back to pending count if queue fails? The original phase 1 loop already counted it
				// either in domainsToTry or pending. If it was in domainsToTry and failed queueing,
				// it should arguably be counted as pending for this cycle's results.
				// Let's recalculate counts at the end for accuracy.

			} // end select
		} // end for domainsToTry
		if config.Verbose && (queuedCount > 0 || failedToPrepareCount > 0) {
			log.Printf("Queued %d packets, failed to prepare %d.", queuedCount, failedToPrepareCount)
		}
	} // end if len(domainsToTry) > 0

	// --- Phase 3: Recalculate final counts based on potentially updated states ---
	finalResponded, finalFailed, finalPending := 0, 0, 0
	domainStatesMutex.Lock()
	for _, status := range domainStates {
		if status.Responded {
			finalResponded++
		} else if status.AttemptsMade >= maxRetries {
			finalFailed++
		} else {
			// Includes domains waiting for timeout (AttemptsMade > 0)
			// AND domains that failed queuing (AttemptsMade might be 0 or >0 but LastAttempt not updated)
			// AND domains successfully queued in this cycle.
			finalPending++
		}
	}
	domainStatesMutex.Unlock()

	return finalResponded, finalFailed, finalPending
}

// calculateAndSendStats gathers current stats and sends them to the collector.
func calculateAndSendStats(xsk *xdp.Socket, startTime time.Time, lastRawStats xdp.Stats, totalDomains, respCount, failCount, retryPendCount int, statsUpdateChan chan<- StatsUpdateData) xdp.Stats {
	now := time.Now()
	duration := now.Sub(startTime).Seconds()
	currentReceived := atomic.LoadUint64(&receivedPackets)
	curRawStats, _ := xsk.Stats() // Get current raw XDP stats

	// Calculate raw rate based on *completed* packets (sent and confirmed by NIC)
	intervalPacketsRaw := curRawStats.Completed - lastRawStats.Completed
	// Assuming a fixed interval based on the manager's ticker (adjust if different)
	intervalSeconds := 500.0 / 1000.0 // TODO: Make this dynamic or pass ticker interval
	intervalRateRaw := uint64(0)
	if intervalSeconds > 0 {
		intervalRateRaw = uint64(float64(intervalPacketsRaw) / intervalSeconds)
	}
	avgRateRaw := 0.0
	if duration > 0 {
		avgRateRaw = float64(curRawStats.Completed) / duration
	}

	updateData := StatsUpdateData{
		TotalDomains:        totalDomains,
		RespondedDomains:    respCount,
		RetryingDomains:     retryPendCount,
		FailedDomains:       failCount,
		ReceivedPackets:     currentReceived,
		PacketsSentRaw:      curRawStats.Completed, // Use completed count
		PacketsPerSecRaw:    intervalRateRaw,
		AvgPacketsPerSecRaw: avgRateRaw,
		Duration:            duration,
	}

	// Non-blocking send to stats channel
	select {
	case statsUpdateChan <- updateData:
	default: // Stats channel full, receiver is lagging; discard update
	}

	return curRawStats // Return current stats to be used as lastRawStats in next iteration
}

// generateFinalReport prints the summary results.
func generateFinalReport(domainStates map[string]*DomainStatus, domainStatesMutex *sync.Mutex, startTime time.Time, xsk *xdp.Socket, config *Config) {
	log.Println("Generating final report...")
	finalResponded := 0
	finalFailed := 0
	failedDomainsList := []string{}

	domainStatesMutex.Lock()
	// Final cache check for any very late responses
	// Assumes 'cache' is accessible (global from bpf.go)
	for fqdn, status := range domainStates {
		if !status.Responded {
			if _, found := cache.Get(fqdn); found {
				if config.Verbose {
					log.Printf("Domain %s marked as responded during final cache check.", fqdn)
				}
				status.Responded = true // Mark based on final cache check
			}
		}
		// Count based on the final status
		if status.Responded {
			finalResponded++
		} else {
			finalFailed++
			if len(failedDomainsList) < 20 { // Limit printing list size
				failedDomainsList = append(failedDomainsList, fqdn)
			}
		}
	}
	totalFinalDomains := len(domainStates)
	domainStatesMutex.Unlock()
	log.Println("Final report generation complete.")

	// Use fmt for final summary block
	fmt.Printf("\n--- Final Summary ---\n")
	fmt.Printf("Total Domains: %d\n", totalFinalDomains)
	fmt.Printf("Responded:     %d\n", finalResponded)
	fmt.Printf("Failed:        %d\n", finalFailed)
	fmt.Printf("Total Runtime: %.2f seconds\n", time.Since(startTime).Seconds())
	finalReceived := atomic.LoadUint64(&receivedPackets)
	fmt.Printf("Total Packets Received (BPF): %d\n", finalReceived)
	finalSentXDP, _ := xsk.Stats()
	fmt.Printf("Total Packets Sent (XDP Completed): %d\n", finalSentXDP.Completed)
	if finalFailed > 0 {
		fmt.Println("\nDomains without responses (limit 20):")
		for _, domain := range failedDomainsList {
			fmt.Printf("- %s\n", domain)
		}
		if finalFailed > len(failedDomainsList) {
			fmt.Printf("- ... (and %d more)\n", finalFailed-len(failedDomainsList))
		}
	}
	fmt.Println("---------------------")
}

// transmitPackets is the main orchestration function.
// transmitPackets is the main orchestration function.
func transmitPackets(xsk *xdp.Socket, initialDomains []string, config *Config, shutdownChan <-chan struct{}) error {
	// --- State Initialization ---
	domainStates := make(map[string]*DomainStatus)
	var domainStatesMutex sync.Mutex
	totalDomains := len(initialDomains)

	fqdnDomains := make([]string, totalDomains)
	for i, domain := range initialDomains {
		fqdn := dns.Fqdn(domain)
		fqdnDomains[i] = fqdn
		domainStates[fqdn] = &DomainStatus{
			AttemptsMade: 0,
			Responded:    false,
			// LastAttempt is initialized implicitly to zero time
		}
	}

	totalDomains = len(domainStates)
	log.Printf("Initialized state for %d domains.", totalDomains)

	// --- Concurrency Setup --- (remains the same)
	packetQueue := make(chan PacketInfo, len(initialDomains)*2) // Buffer size might need tuning
	stopStats := make(chan struct{})
	programDone := make(chan struct{})
	var senderWg sync.WaitGroup
	statsUpdateChan := make(chan StatsUpdateData, 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Rate Limiter Setup --- (remains the same)
	rateLimit := rate.Limit(config.RateLimitPPS)
	burstSize := config.MaxBatchSize
	if burstSize < 1 {
		burstSize = 1
	}
	limiter := rate.NewLimiter(rateLimit, burstSize)
	log.Printf("Rate limiter configured: Limit=%.2f PPS, Burst=%d", rateLimit, burstSize)

	// --- Start Goroutines --- (remains the same)
	go statsCollector(statsUpdateChan, stopStats, programDone, config)
	senderWg.Add(1)
	go packetSender(ctx, xsk, packetQueue, limiter, &senderWg, config, domainStates, &domainStatesMutex) // Added state arguments

	// --- Initial Setup --- (remains the same)
	rng := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
	link, err := netlink.LinkByName(config.NIC)
	if err != nil {
		log.Fatalf("Failed to get link by name: %v", err)
	}
	srcMAC, dstMAC, err := ResolveMACAddresses(config, link)
	if err != nil {
		log.Fatalf("Failed to resolve MAC addresses: %v", err)
	}
	srcIP := net.ParseIP(config.SrcIP)
	if srcIP == nil {
		log.Fatalf("Failed to parse source IP: %v", err)
	}
	// --- Queue Initial Batch ---
	queueInitialDomains(fqdnDomains, packetQueue, domainStates, &domainStatesMutex, srcIP, srcMAC, dstMAC, config, rng)
	log.Printf("Queued %d initial packets.", len(packetQueue)) // Log current queue size

	// --- Main Management Loop ---
	startTime := time.Now()
	ticker := time.NewTicker(1 * time.Second) // Check status/retries less frequently? Adjust as needed.
	defer ticker.Stop()
	var lastRawStats xdp.Stats

loop:
	for {
		// Check domain states and queue retries/initial attempts
		respCount, failCount, pendingCount := checkAndRetryDomains(domainStates, &domainStatesMutex, packetQueue, srcIP, srcMAC, dstMAC, config, rng)

		// Send stats update regardless of completion status
		lastRawStats = calculateAndSendStats(xsk, startTime, lastRawStats, totalDomains, respCount, failCount, pendingCount, statsUpdateChan)
		// Check for completion condition
		if respCount+failCount == totalDomains {
			// Ensure pending is 0, otherwise something is wrong with the logic
			if pendingCount != 0 {
				log.Printf("Warning: Completion condition met (Responded=%d, Failed=%d, Total=%d), but Pending count is %d. Logic error?", respCount, failCount, totalDomains, pendingCount)
			}
			log.Printf("All domains processed: Responded=%d, Failed=%d, Total=%d", respCount, failCount, totalDomains)
			break loop // Exit the main loop
		}

		// Check for shutdown signal
		select {
		case <-shutdownChan:
			log.Println("Shutdown signal received by manager. Stopping loop.")
			break loop
		case <-ticker.C:
			// Continue loop on next tick - work is done above
			continue
		}
	}

	// --- Shutdown Sequence --- (remains the same)
	log.Println("Stopping packet sender via context cancellation...")
	cancel()
	senderWg.Wait()

	log.Println("Closing packet queue...")
	close(packetQueue) // Close queue *after* sender stops

	log.Println("Stopping statistics collector...")
	close(stopStats)
	<-programDone
	log.Println("Statistics collector stopped.")

	// --- Final Report ---
	// Recalculate final stats directly from domainStates for the report,
	// as the loop might have terminated between checkAndRetryDomains and the report.
	generateFinalReport(domainStates, &domainStatesMutex, startTime, xsk, config)

	return nil
}

// --- JSON Output Structures and Functions ---

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
	Data  string `json:"Data"` // Simplified: Stores string representation of data
}

type PrettyDnsMsg struct {
	TransactionID uint16              `json:"TransactionID"`
	MessageType   string              `json:"MessageType"`
	Opcode        string              `json:"Opcode"`
	ResponseCode  string              `json:"ResponseCode"`
	Flags         PrettyDnsFlags      `json:"Flags"`
	Question      []PrettyDnsQuestion `json:"Question"`
	Answers       []PrettyDnsAnswer   `json:"Answers"`
	Authority     []PrettyDnsAnswer   `json:"Authority"`
	Additional    []PrettyDnsAnswer   `json:"Additional"`
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
		Additional: make([]PrettyDnsAnswer, 0, len(msg.Extra)), // Initialize correctly
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
		var data string

		switch v := rr.(type) {
		case *dns.A:
			data = v.A.String()
		case *dns.AAAA:
			data = v.AAAA.String()
		case *dns.CNAME:
			data = v.Target
		case *dns.MX:
			data = fmt.Sprintf("%d %s", v.Preference, v.Mx)
		case *dns.NS:
			data = v.Ns
		case *dns.PTR:
			data = v.Ptr
		case *dns.SOA:
			data = fmt.Sprintf("%s %s %d %d %d %d %d", v.Ns, v.Mbox, v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl)
		case *dns.SRV:
			data = fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, v.Target)
		case *dns.TXT:
			data = fmt.Sprintf(`"%s"`, strings.Join(v.Txt, `" "`))
		case *dns.OPT:
			return PrettyDnsAnswer{Name: ".", Type: "OPT"} // Special handling for OPT
		default:
			fullString := rr.String()
			headerString := hdr.String()
			if len(fullString) > len(headerString) && strings.HasPrefix(fullString, headerString) {
				data = strings.TrimSpace(fullString[len(headerString):])
			} else {
				data = fullString
			}
		}

		return PrettyDnsAnswer{
			Name:  hdr.Name,
			Type:  dns.TypeToString[hdr.Rrtype],
			Class: dns.ClassToString[hdr.Class],
			TTL:   hdr.Ttl,
			Data:  data,
		}
	}

	for _, rr := range msg.Answer {
		pretty.Answers = append(pretty.Answers, mapRR(rr))
	}
	for _, rr := range msg.Ns {
		pretty.Authority = append(pretty.Authority, mapRR(rr))
	}
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); !ok { // Exclude OPT from Additional section
			pretty.Additional = append(pretty.Additional, mapRR(rr))
		}
	}

	return pretty
}

// saveCachePrettified saves the contents of the response cache to a file in NDJSON format.
// Assumes 'cache' is accessible (global from bpf.go).
func saveCachePrettified(config *Config) {
	if config.OutputFile == "" {
		log.Println("No output file specified (-output), skipping saving results.")
		return
	}
	filename := config.OutputFile

	outFile, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating output file %s: %v", filename, err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	savedCount := 0
	skippedCount := 0

	// Build map for efficient RCODE lookup
	skipCodes := make(map[int]struct{})
	for _, code := range config.CodesToSkip {
		skipCodes[code] = struct{}{}
	}

	// Iterate through the cache (assuming cache stores *dns.Msg)
	cache.ForEach(func(domainKey string, responseMsg *dns.Msg) bool {
		if responseMsg != nil {
			// Check if the response code should be skipped
			if _, skip := skipCodes[responseMsg.Rcode]; skip {
				skippedCount++
				return true // Continue ForEach, skip this entry
			}

			prettyMsg := prettifyDnsMsg(responseMsg)
			if prettyMsg == nil {
				log.Printf("Warning: Could not prettify message for domain %s", domainKey)
				return true // Continue ForEach
			}

			jsonData, err := json.Marshal(prettyMsg)
			if err != nil {
				log.Printf("Error marshalling pretty result for %s: %v", domainKey, err)
				return true // Continue ForEach
			}

			_, err = writer.Write(jsonData)
			if err == nil {
				_, err = writer.WriteString("\n") // NDJSON format
			}

			if err != nil {
				log.Printf("Error writing pretty result for %s to file %s: %v", domainKey, filename, err)
				// Continue processing other cache entries even if one fails to write
			} else {
				savedCount++
			}
		}
		return true // Continue iterating through the cache
	})

	log.Printf("Saved %d records to %s (skipped %d due to RCODE filter).", savedCount, filename, skippedCount)
}

// --- Main Function ---

func main() {
	// --- Configuration and Flag Parsing ---
	config := DefaultConfig()

	domainsFile := flag.String("domains", "", "File containing domains to query (one per line)")
	nameserversFile := flag.String("nameservers", "", "File containing nameservers to use (one per line)")

	flag.StringVar(&config.NIC, "interface", config.NIC, "Network interface")
	flag.IntVar(&config.QueueID, "queue", config.QueueID, "Interface queue ID")
	flag.StringVar(&config.SrcMAC, "srcmac", config.SrcMAC, "Source MAC (optional, uses interface MAC if empty)")
	flag.StringVar(&config.DstMAC, "dstmac", config.DstMAC, "Destination MAC (optional, resolves via ARP if empty)")
	flag.StringVar(&config.SrcIP, "srcip", config.SrcIP, "Source IP (optional, uses interface IP if empty)")
	flag.StringVar(&config.DomainName, "domain", config.DomainName, "Single domain to query (overridden by -domains)")
	flag.DurationVar(&config.RetryTimeout, "retry-timeout", config.RetryTimeout, "Retry timeout")
	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "Enable verbose logging")
	flag.IntVar(&config.PollTimeoutMs, "poll", config.PollTimeoutMs, "XDP socket poll timeout (ms)")
	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "File to save results (NDJSON)")
	flag.IntVar(&config.Retries, "retries", config.Retries, "Retries per domain")
	flag.IntVar(&config.MaxBatchSize, "maxbatch", config.MaxBatchSize, "Max XDP TX batch size")
	flag.IntVar(&config.RateLimitPPS, "rate", config.RateLimitPPS, "Target packets per second rate limit for sending") // Added flag
	// TODO: Add flag for CodesToSkip if needed
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// --- Input Validation ---
	if config.NIC == "" {
		log.Fatal("Error: Network interface (-interface) is required")
	}
	if config.RateLimitPPS <= 0 {
		log.Fatal("Error: Rate limit (-rate) must be positive")
	}
	if config.MaxBatchSize <= 0 {
		log.Fatal("Error: Max batch size (-maxbatch) must be positive")
	}

	// --- Signal Handling for Graceful Shutdown ---
	shutdownChan := make(chan struct{}) // Signals graceful shutdown to manager
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v. Initiating graceful shutdown...", sig)
		close(shutdownChan) // Signal manager loop to stop

		// Give manager time to signal components
		<-time.After(5 * time.Second)
		log.Println("Shutdown timeout reached. Forcing exit.")
		os.Exit(1)
	}()

	// --- Network Setup ---
	link, err := netlink.LinkByName(config.NIC)
	if err != nil {
		log.Fatalf("Error: couldn't find interface %s: %v", config.NIC, err)
	}

	if config.SrcIP == "" {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil || len(addrs) == 0 {
			log.Fatalf("Error: failed to get IPv4 address for interface %s: %v", config.NIC, err)
		}
		config.SrcIP = addrs[0].IP.String()
		log.Printf("Using source IP %s from interface %s", config.SrcIP, config.NIC)
	}

	// --- Start BPF Receiver ---
	// ... (BPF setup remains the same) ...
	bpfExited := make(chan struct{}) // Closed when BPF goroutine fully exits
	go func() {
		defer close(bpfExited)
		BpfReceiver(config) // Assumes BpfReceiver exists in bpf.go
		log.Println("BPF Receiver goroutine finished.")
	}()
	select {
	case <-startedBPF:
		log.Println("BPF receiver started successfully.")
	case <-time.After(5 * time.Second): // Timeout for BPF startup
		log.Fatal("Error: Timed out waiting for BPF receiver to start.")
	}

	// --- Load Domains ---
	// ... (Domain loading remains the same) ...
	var domains []string
	if *domainsFile != "" {
		loadedDomains, err := readDomainsFromFile(*domainsFile)
		if err != nil {
			log.Fatalf("Error reading domains file '%s': %v", *domainsFile, err)
		}
		domains = loadedDomains
		log.Printf("Loaded %d domains from %s", len(domains), *domainsFile)
	} else if config.DomainName != "" {
		domains = []string{config.DomainName}
		log.Printf("Using single domain: %s", config.DomainName)
	} else {
		log.Fatal("Error: Must provide a domain via -domain or a list via -domains")
	}

	// --- Load Nameservers ---
	// ... (Nameserver loading remains the same) ...
	if *nameserversFile != "" {
		loadedNameservers, err := readDomainsFromFile(*nameserversFile)
		if err != nil {
			log.Fatalf("Error reading nameservers file '%s': %v", *nameserversFile, err)
		}
		config.Nameservers = loadedNameservers
		log.Printf("Loaded %d nameservers from %s", len(config.Nameservers), *nameserversFile)
	} else if len(config.Nameservers) > 0 {
		log.Printf("Using default nameservers: %v", config.Nameservers)
	} else {
		log.Fatal("Error: No nameservers loaded or defined in default config.")
	}

	// --- Initialize XDP Socket ---
	opts := &xdp.SocketOptions{
		NumFrames:              4096,
		FrameSize:              2048,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 2048,
		RxRingNumDescs:         64,
		TxRingNumDescs:         2048,
		// Flags: xdp.XdpFlagsNeedWakeup, // Consider if using blocking Poll/Wait
	}
	log.Printf("Initializing XDP socket on interface %s queue %d", config.NIC, config.QueueID)
	xsk, err := xdp.NewSocket(link.Attrs().Index, config.QueueID, opts)
	if err != nil {
		log.Fatalf("Error creating XDP socket on %s queue %d: %v. Ensure driver support and sufficient privileges.", config.NIC, config.QueueID, err)
	}
	defer func() {
		log.Println("Closing XDP socket...")
		xsk.Close()
		log.Println("XDP socket closed.")
	}()

	// --- Start Transmission and Management ---
	log.Println("Starting packet transmission process...")
	err = transmitPackets(xsk, domains, config, shutdownChan)
	if err != nil {
		log.Printf("Transmission process encountered an error: %v", err)
	} else {
		log.Println("Transmission process completed.")
	}

	// --- Save Results ---
	log.Println("Saving results from cache...")
	saveCachePrettified(config)

	// --- Stop BPF Receiver ---
	log.Println("Signaling BPF receiver to stop...")
	close(stopper) // Assumes stopper exists in bpf.go
	log.Println("Waiting for BPF receiver to exit gracefully...")
	select {
	case <-bpfExited:
		log.Println("BPF receiver exited.")
	case <-time.After(5 * time.Second):
		log.Println("Warning: Timed out waiting for BPF receiver to exit.")
	}

	log.Println("PugDNS finished.")
}
