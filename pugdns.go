package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"

	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/rand"
	"golang.org/x/sys/unix"
)

type PacketInfo struct {
	Domain      string
	PacketBytes []byte
	Attempt     int
}

type DomainStatus struct {
	mu           sync.Mutex
	AttemptsMade int
	Responded    bool
	LastAttempt  time.Time
}

type StatsUpdateData struct {
	TotalDomains        int
	RespondedDomains    int
	RetryingDomains     int
	FailedDomains       int
	ReceivedPackets     uint64
	PacketsSentRaw      uint64
	PacketsPerSecRaw    uint64
	AvgPacketsPerSecRaw float64
	Duration            float64
}

// Performance-related globals
var (
	performanceTimings = make(map[string]*atomic.Uint64)
	performanceCounts  = make(map[string]*atomic.Uint64)
	performanceMutex   sync.Mutex
)

var receivedPackets uint64
var statsPacketSentAttempted uint64
var totalDomainsProcessed uint64

func readDomainsFromFile(filename string) ([]string, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	// Read the entire file content into memory
	contentBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file '%s': %w", filename, err)
	}

	content := string(contentBytes)
	lines := strings.Split(content, "\n")

	// Pre-allocate slice with a reasonable capacity estimate if possible,
	// although len(lines) might overestimate significantly due to comments/blanks.
	// Starting with 0 capacity is safe and often performant enough.
	items := make([]string, 0)

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		// Skip empty lines and lines starting with #
		if trimmedLine != "" {
			items = append(items, trimmedLine)
		}
	}

	if len(items) == 0 {
		// Check if the file was completely empty or only contained comments/whitespace
		if len(contentBytes) == 0 {
			return nil, fmt.Errorf("file '%s' is empty", filename)
		}
		return nil, fmt.Errorf("no valid, non-comment items found in file '%s'", filename)
	}

	return items, nil
}

func checksum(buf []byte) uint16 {
	var sum uint32
	for ; len(buf) >= 2; buf = buf[2:] {
		sum += uint32(buf[0])<<8 | uint32(buf[1])
	}
	if len(buf) > 0 {
		sum += uint32(buf[0]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func createPacketTemplate(srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, config *Config) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    net.ParseIP("1.1.1.1"), // Placeholder, will be replaced
		Flags:    layers.IPv4DontFragment,
	}
	udp := &layers.UDP{
		SrcPort: 0, // Placeholder
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: false} // Checksums will be calculated manually
	// Serialize with a dummy payload to get the correct header structure
	err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload([]byte{0}))
	if err != nil {
		return nil, fmt.Errorf("serializing template layers: %w", err)
	}

	// We only want the headers, not the dummy payload
	return buf.Bytes()[:14+20+8], nil
}

func prepareSinglePacket(packetTemplate []byte, fqdn string, nameserverIP net.IP, rng *rand.Rand) ([]byte, error) {
	defer timeOperation("PacketPrep")()

	// 1. Create DNS query
	query := new(dns.Msg)
	query.Id = uint16(rng.Intn(65535))
	query.RecursionDesired = true
	query.Question = []dns.Question{{
		Name:   fqdn,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}}
	query.SetEdns0(4096, false)
	dnsPayload, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("packing DNS query for %s: %w", fqdn, err)
	}

	// 2. Create the final packet from template and payload
	packet := make([]byte, len(packetTemplate)+len(dnsPayload))
	copy(packet, packetTemplate)
	copy(packet[len(packetTemplate):], dnsPayload)

	// 3. Get header slices for mutation
	ipHeader := packet[14:34]
	udpHeader := packet[34:42]

	// 4. Update lengths
	ipTotalLen := uint16(20 + 8 + len(dnsPayload)) // IP header + UDP header + DNS
	udpTotalLen := uint16(8 + len(dnsPayload))     // UDP header + DNS
	binary.BigEndian.PutUint16(ipHeader[2:4], ipTotalLen)
	binary.BigEndian.PutUint16(udpHeader[4:6], udpTotalLen)

	// 5. Update dynamic fields
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(rng.Intn(65535)))            // IP ID
	copy(ipHeader[16:20], nameserverIP.To4())                                     // Dst IP
	binary.BigEndian.PutUint16(udpHeader[0:2], uint16(1024+rng.Intn(65535-1024))) // Src Port

	// 6. Calculate checksums
	// Clear checksum fields first
	ipHeader[10] = 0
	ipHeader[11] = 0
	udpHeader[6] = 0
	udpHeader[7] = 0

	// IP Checksum
	ipCsum := checksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], ipCsum)

	// UDP Checksum
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipHeader[12:16]) // srcIP from template
	copy(pseudoHeader[4:8], ipHeader[16:20]) // dstIP (just updated)
	pseudoHeader[8] = 0                      // reserved
	pseudoHeader[9] = 17                     // UDP protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], udpTotalLen)

	udpCsumBuf := make([]byte, 0, len(pseudoHeader)+int(udpTotalLen))
	udpCsumBuf = append(udpCsumBuf, pseudoHeader...)
	udpCsumBuf = append(udpCsumBuf, packet[34:]...) // Append UDP header and payload

	udpCsum := checksum(udpCsumBuf)
	if udpCsum == 0 {
		udpCsum = 0xffff // If checksum is 0, it should be sent as all 1s.
	}
	binary.BigEndian.PutUint16(udpHeader[6:8], udpCsum)

	return packet, nil
}

func packetSender(ctx context.Context, xsk *xdp.Socket, packetQueue <-chan PacketInfo, wg *sync.WaitGroup, config *Config, domainStates *haxmap.Map[string, *DomainStatus]) {
	defer wg.Done()
	log.Println("Packet sender started.")

	maxBatchSize := config.MaxBatchSize
	pollTimeout := config.PollTimeoutMs

	for {

		_, _, pollErr := xsk.Poll(0)
		if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR && pollErr != unix.EAGAIN {
			log.Printf("Sender Poll error: %v", pollErr)
		} else {
			numCompleted := xsk.NumCompleted()
			if numCompleted > 0 {
				xsk.Complete(numCompleted)
			}
		}

		select {
		case <-ctx.Done():
			log.Println("Packet sender received stop signal via context. Finalizing...")
			finalizeTransmission(xsk, config)
			log.Println("Packet sender finished.")
			return
		default:
		}

		// Smart batching: determine batch size based on waiting packets and free slots.
		packetsInQueue := len(packetQueue)
		if packetsInQueue == 0 {
			runtime.Gosched() // No work to do, yield.
			continue
		}

		freeSlots := xsk.NumFreeTxSlots()
		if freeSlots == 0 {
			pollStart := time.Now()
			_, _, pollErr = xsk.Poll(pollTimeout)
			recordTiming("Sender_PollWait", time.Since(pollStart))

			if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR {
				log.Printf("Sender Poll(timeout) error: %v", pollErr)
			}
			numCompleted := xsk.NumCompleted()
			if numCompleted > 0 {
				xsk.Complete(numCompleted)
			}
			freeSlots = xsk.NumFreeTxSlots()
			if freeSlots == 0 {
				runtime.Gosched()
				continue
			}
		}

		// Request a number of descriptors matching the smaller of available packets or free slots.
		descsToRequest := packetsInQueue
		if descsToRequest > freeSlots {
			descsToRequest = freeSlots
		}
		if descsToRequest > maxBatchSize {
			descsToRequest = maxBatchSize
		}
		if descsToRequest == 0 {
			runtime.Gosched()
			continue
		}

		getDescsStart := time.Now()
		descs := xsk.GetDescs(descsToRequest, false)
		recordTiming("Sender_GetDescs", time.Since(getDescsStart))

		if len(descs) == 0 {
			runtime.Gosched()
			continue
		}

		packetsToSend := make([]PacketInfo, 0, len(descs))
		descsFilled := 0

		fillLoopStart := time.Now()
	fillLoop:
		for i := 0; i < len(descs); i++ {
			select {
			case pktInfo, ok := <-packetQueue:
				if !ok {
					log.Println("Packet queue closed. Sender stopping fill loop.")
					break fillLoop
				}
				if len(pktInfo.PacketBytes) == 0 {
					log.Printf("Warning: Empty packet bytes for domain %s", pktInfo.Domain)
					continue
				}

				frame := xsk.GetFrame(descs[descsFilled])
				if len(frame) < len(pktInfo.PacketBytes) {
					log.Printf("Error: Frame size (%d) too small for packet (%d bytes) for domain %s. Skipping.", len(frame), len(pktInfo.PacketBytes), pktInfo.Domain)
					continue
				}

				frameLen := copy(frame, pktInfo.PacketBytes)
				descs[descsFilled].Len = uint32(frameLen)

				packetsToSend = append(packetsToSend, pktInfo)
				descsFilled++

			default:
				break fillLoop
			}
		}
		recordTiming("Sender_FillLoop", time.Since(fillLoopStart))

		if descsFilled > 0 {
			now := time.Now()
			for _, pktInfo := range packetsToSend {
				if status, ok := domainStates.Get(pktInfo.Domain); ok {
					status.mu.Lock()
					if !status.Responded {
						status.LastAttempt = now
					}
					status.mu.Unlock()
				}
			}

			transmitStart := time.Now()
			numSubmitted := xsk.Transmit(descs[:descsFilled])
			recordTiming("Sender_Transmit", time.Since(transmitStart))
			atomic.AddUint64(&statsPacketSentAttempted, uint64(descsFilled))

			if numSubmitted < descsFilled {
				log.Printf("Warning: Sender failed to submit %d packets (%d/%d). Manager will retry.", descsFilled-numSubmitted, numSubmitted, descsFilled)
			}
		} else {
			runtime.Gosched()
		}

		select {
		case <-ctx.Done():
			break
		default:

		}

	}

}

func finalizeTransmission(xsk *xdp.Socket, config *Config) {
	if config.Verbose {
		log.Println("Starting transmission finalization...")
	}
	startTime := time.Now()
	timeout := 1000 * time.Millisecond

	for time.Since(startTime) < timeout {
		numTransmitting := xsk.NumTransmitted()
		if numTransmitting == 0 {
			if config.Verbose {
				log.Printf("Finalization: No packets transmitting after %.2fs.", time.Since(startTime).Seconds())
			}
			break
		}

		_, _, pollErr := xsk.Poll(20)
		if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR {
			log.Printf("Final poll error: %v", pollErr)
		}

		completed := xsk.NumCompleted()
		if completed > 0 {
			xsk.Complete(completed)
			if config.Verbose {
				log.Printf("Finalization: Completed %d packets", completed)
			}

		} else if pollErr == unix.ETIMEDOUT || pollErr == unix.EINTR || pollErr == nil {
			runtime.Gosched()
		} else {
			break
		}
	}

	finalNumTransmitting := xsk.NumTransmitted()
	if finalNumTransmitting > 0 {
		log.Printf("Warning: Finalization finished, but %d packets still marked as transmitting.", finalNumTransmitting)
	} else if config.Verbose {
		log.Println("Finalization complete.")
	}
}

func statsCollector(updateChan <-chan StatsUpdateData, stopStats <-chan struct{}, programDone chan<- struct{}, config *Config) {
	log.Println("Statistics collector started.")
	var lastUpdate StatsUpdateData
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	running := true

	for running {
		select {
		case updateData, ok := <-updateChan:
			if !ok {
				running = false
				break
			}
			lastUpdate = updateData

		case <-ticker.C:
			if lastUpdate.TotalDomains > 0 {
				prog := 0.0

				prog = float64(lastUpdate.RespondedDomains+lastUpdate.FailedDomains) / float64(lastUpdate.TotalDomains) * 100

				log.Printf("\rD:%d | Rsp:%d | Fail:%d | Pend:%d | Rx:%d | RawTX:%d | RawRate:%d pps | RawAvg:%.1f pps | Time:%.1fs | Prog:%.1f%% ",
					lastUpdate.TotalDomains, lastUpdate.RespondedDomains, lastUpdate.FailedDomains, lastUpdate.RetryingDomains,
					lastUpdate.ReceivedPackets, lastUpdate.PacketsSentRaw, lastUpdate.PacketsPerSecRaw,
					lastUpdate.AvgPacketsPerSecRaw, lastUpdate.Duration, prog)
			}

		case <-stopStats:
			running = false
			break
		}
	}

	fmt.Println()
	log.Println("Statistics collector shutting down.")

	if lastUpdate.TotalDomains > 0 {
		prog := float64(lastUpdate.RespondedDomains+lastUpdate.FailedDomains) / float64(lastUpdate.TotalDomains) * 100
		log.Printf("Final Stats: D:%d | Rsp:%d | Fail:%d | Pend:%d | Rx:%d | RawTX:%d | RawRate:%d pps | RawAvg:%.1f pps | Time:%.1fs | Prog:%.1f%% ",
			lastUpdate.TotalDomains, lastUpdate.RespondedDomains, lastUpdate.FailedDomains, lastUpdate.RetryingDomains,
			lastUpdate.ReceivedPackets, lastUpdate.PacketsSentRaw, lastUpdate.PacketsPerSecRaw,
			lastUpdate.AvgPacketsPerSecRaw, lastUpdate.Duration, prog)
	}
	programDone <- struct{}{}
}

func calculateAndSendStats(xsk *xdp.Socket, startTime time.Time, lastRawStats xdp.Stats, totalDomainsInFile int, domainsCurrentlyManaged int, statsUpdateChan chan<- StatsUpdateData) xdp.Stats {
	now := time.Now()
	duration := now.Sub(startTime).Seconds()
	currentReceived := atomic.LoadUint64(&receivedPackets)
	curProcessed := atomic.LoadUint64(&totalDomainsProcessed)
	curRawStats, _ := xsk.Stats()

	intervalPacketsRaw := curRawStats.Completed - lastRawStats.Completed

	intervalSeconds := 1.0
	intervalRateRaw := uint64(0)
	if intervalSeconds > 0 {
		intervalRateRaw = uint64(float64(intervalPacketsRaw) / intervalSeconds)
	}
	avgRateRaw := 0.0
	if duration > 0 {
		avgRateRaw = float64(curRawStats.Completed) / duration
	}

	finalRespondedApproxUintPtr := cache.Len()
	finalRespondedApprox := int(finalRespondedApproxUintPtr)
	finalFailedApprox := int(curProcessed) - finalRespondedApprox
	if finalFailedApprox < 0 {
		finalFailedApprox = 0
	}

	updateData := StatsUpdateData{
		TotalDomains:        totalDomainsInFile,
		RespondedDomains:    finalRespondedApprox,
		RetryingDomains:     domainsCurrentlyManaged,
		FailedDomains:       finalFailedApprox,
		ReceivedPackets:     currentReceived,
		PacketsSentRaw:      curRawStats.Completed,
		PacketsPerSecRaw:    intervalRateRaw,
		AvgPacketsPerSecRaw: avgRateRaw,
		Duration:            duration,
	}

	select {
	case statsUpdateChan <- updateData:
	default:
	}

	return curRawStats
}

func generateFinalReport(failedDomainsList []string, totalDomainsInFile int, startTime time.Time, xsk *xdp.Socket, config *Config) {
	log.Println("Generating final report...")

	skipCodes := make(map[int]struct{})
	for _, code := range config.CodesToSkip {
		skipCodes[code] = struct{}{}
	}
	finalResponded := 0
	cache.ForEach(func(domainKey string, responseMsg *dns.Msg) bool {
		if responseMsg != nil {
			if _, skip := skipCodes[responseMsg.Rcode]; !skip {
				finalResponded++
			}
		}
		return true
	})

	finalFailed := len(failedDomainsList)

	totalProcessedReport := finalResponded + finalFailed
	globalProcessed := atomic.LoadUint64(&totalDomainsProcessed)

	log.Println("Final report generation complete.")

	fmt.Printf("\n--- Final Summary ---\n")
	fmt.Printf("Total Domains Queried: %d (processed %d, report count %d)\n", totalDomainsInFile, globalProcessed, totalProcessedReport)
	if int(globalProcessed) != totalProcessedReport {
		fmt.Printf("  Warning: Discrepancy between final processed counter (%d) and report sum (%d)\n", globalProcessed, totalProcessedReport)
	}
	fmt.Printf("Responded (in output file): %d\n", finalResponded)
	fmt.Printf("Failed (no valid response): %d\n", finalFailed)
	fmt.Printf("Total Runtime: %.2f seconds\n", time.Since(startTime).Seconds())
	finalReceived := atomic.LoadUint64(&receivedPackets)
	fmt.Printf("Total Packets Received (BPF): %d\n", finalReceived)
	finalSentXDP, _ := xsk.Stats()
	fmt.Printf("Total Packets Sent (XDP Completed): %d\n", finalSentXDP.Completed)
	if finalFailed > 0 {
		fmt.Println("\nDomains without valid responses (limit 20):")
		limit := 20
		if finalFailed < limit {
			limit = finalFailed
		}
		for i := 0; i < limit; i++ {
			fmt.Printf("- %s\n", failedDomainsList[i])
		}
		if finalFailed > limit {
			fmt.Printf("- ... (and %d more)\n", finalFailed-limit)
		}
	}
	fmt.Println("---------------------")
}

func feedDomainsToQueue(domainsToFeed []string, packetQueue chan<- PacketInfo, domainStates *haxmap.Map[string, *DomainStatus], packetTemplate []byte, config *Config, rng *rand.Rand) int {
	if config.Verbose {
		log.Printf("Feeding batch of %d domains...", len(domainsToFeed))
	}
	addedAndQueued := 0
	now := time.Now()

	for _, fqdn := range domainsToFeed {
		if len(config.Nameservers) == 0 {
			log.Printf("Error preparing packet for %s: No nameservers configured. Skipping this domain.", fqdn)
			atomic.AddUint64(&totalDomainsProcessed, 1)
			continue
		}
		currentNameserver := config.Nameservers[rng.Intn(len(config.Nameservers))]
		dstIP := net.ParseIP(currentNameserver)
		if dstIP == nil {
			log.Printf("Error preparing packet for %s: Invalid nameserver IP %s. Skipping this domain.", fqdn, currentNameserver)
			atomic.AddUint64(&totalDomainsProcessed, 1)
			continue
		}

		packetBytes, err := prepareSinglePacket(packetTemplate, fqdn, dstIP, rng)
		if err != nil {
			log.Printf("Error preparing initial packet for %s: %v. Skipping this domain.", fqdn, err)
			atomic.AddUint64(&totalDomainsProcessed, 1)
			continue
		}
		pktInfo := PacketInfo{Domain: fqdn, PacketBytes: packetBytes, Attempt: 1}

		// Set the new domain status. Haxmap handles concurrent writes.
		// We only do this once per domain, so a simple Set is fine.
		domainStates.Set(fqdn, &DomainStatus{
			AttemptsMade: 1,
			Responded:    false,
			LastAttempt:  now,
		})
		addedAndQueued++

		packetQueue <- pktInfo
	}
	if config.Verbose {
		log.Printf("Fed batch complete. Added/Queued %d domains.", addedAndQueued)
	}
	return addedAndQueued
}

func checkAndRetryDomains(domainStates *haxmap.Map[string, *DomainStatus], packetQueue chan<- PacketInfo, packetTemplate []byte, config *Config, rng *rand.Rand, failedDomainsList *[]string) (pendingCount int) {
	defer timeOperation("Manager_RetryCheck")()
	now := time.Now()
	domainsToRetry := make(map[string]int) // map fqdn to current attempt count
	domainsToRemove := []string{}
	maxRetries := config.Retries + 1
	var currentPending int

	domainStates.ForEach(func(fqdn string, status *DomainStatus) bool {
		status.mu.Lock()

		if !status.Responded {
			if _, found := cache.Get(fqdn); found {
				status.Responded = true
			}
		}

		if status.Responded {
			domainsToRemove = append(domainsToRemove, fqdn)
			atomic.AddUint64(&totalDomainsProcessed, 1)
		} else if status.AttemptsMade >= maxRetries {
			domainsToRemove = append(domainsToRemove, fqdn)
			*failedDomainsList = append(*failedDomainsList, fqdn)
			atomic.AddUint64(&totalDomainsProcessed, 1)
		} else if !status.LastAttempt.IsZero() && now.Sub(status.LastAttempt) > config.RetryTimeout {
			domainsToRetry[fqdn] = status.AttemptsMade
		} else {
			currentPending++
		}

		status.mu.Unlock()
		return true // Continue iteration
	})

	for _, fqdn := range domainsToRemove {
		domainStates.Del(fqdn)
	}

	queuedCount := 0
	failedToPrepareCount := 0

	if len(domainsToRetry) > 0 {
		for fqdn, currentAttempt := range domainsToRetry {
			currentNameserver := config.Nameservers[rng.Intn(len(config.Nameservers))]
			dstIP := net.ParseIP(currentNameserver)
			if dstIP == nil {
				log.Printf("Error preparing retry packet for %s: Invalid nameserver IP %s. Marking failed.", fqdn, currentNameserver)
				failedToPrepareCount++
				domainStates.Del(fqdn)
				*failedDomainsList = append(*failedDomainsList, fqdn)
				atomic.AddUint64(&totalDomainsProcessed, 1)
				continue
			}
			packetBytes, err := prepareSinglePacket(packetTemplate, fqdn, dstIP, rng)
			if err != nil {
				log.Printf("Error preparing retry packet for %s (attempt %d): %v. Marking failed.", fqdn, currentAttempt+1, err)
				failedToPrepareCount++
				domainStates.Del(fqdn)
				*failedDomainsList = append(*failedDomainsList, fqdn)
				atomic.AddUint64(&totalDomainsProcessed, 1)
				continue
			}

			pktInfo := PacketInfo{Domain: fqdn, PacketBytes: packetBytes, Attempt: currentAttempt + 1}
			packetQueue <- pktInfo
			queuedCount++

			if status, ok := domainStates.Get(fqdn); ok {
				status.mu.Lock()
				if !status.Responded {
					status.AttemptsMade++
					status.LastAttempt = time.Now()
				}
				status.mu.Unlock()
			}
		}
	}

	return int(domainStates.Len())
}

func transmitPackets(xsk *xdp.Socket, allInputDomains []string, config *Config, shutdownChan <-chan struct{}) error {

	domainStates := haxmap.New[string, *DomainStatus]()
	var failedDomainsList []string

	initialTotalDomains := len(allInputDomains)
	if initialTotalDomains == 0 {
		log.Println("No domains to process.")
		return nil
	}
	log.Printf("Loaded %d domains. Starting asynchronous preparation...", initialTotalDomains)
	atomic.StoreUint64(&totalDomainsProcessed, 0)

	// --- Channels for async domain processing ---
	processedDomainsChan := make(chan string, config.MaxBatchSize*4)
	uniqueDomainCountChan := make(chan int, 1)

	// --- Start async domain processor ---
	go func(domains []string) {
		log.Println("Async domain processor started.")
		// 1. Normalize and deduplicate
		uniqueFqdns := make(map[string]struct{}, len(domains))

		numWorkers := runtime.NumCPU()
		if numWorkers > len(domains)/1000 && len(domains) > 1000 {
			numWorkers = len(domains) / 1000
		}
		if numWorkers == 0 {
			numWorkers = 1
		}
		fqdnChan := make(chan string, len(domains))
		var wg sync.WaitGroup

		processChunk := func(chunk []string) {
			defer wg.Done()
			for _, domain := range chunk {
				processedDomain := strings.TrimSpace(domain)
				if processedDomain == "" {
					continue
				}
				if !strings.HasSuffix(processedDomain, ".") {
					processedDomain += "."
				}
				fqdnChan <- processedDomain
			}
		}

		chunkSize := (len(domains) + numWorkers - 1) / numWorkers
		wg.Add(numWorkers)
		for i := 0; i < numWorkers; i++ {
			start := i * chunkSize
			end := start + chunkSize
			if end > len(domains) {
				end = len(domains)
			}
			if start >= end {
				wg.Done()
				continue
			}
			go processChunk(domains[start:end])
		}

		go func() {
			wg.Wait()
			close(fqdnChan)
		}()

		for fqdn := range fqdnChan {
			uniqueFqdns[fqdn] = struct{}{}
		}

		log.Printf("Async preparation complete. Processing %d unique FQDN domains.", len(uniqueFqdns))
		uniqueDomainCountChan <- len(uniqueFqdns)
		close(uniqueDomainCountChan)

		// 2. Stream unique domains to the manager
		for fqdn := range uniqueFqdns {
			processedDomainsChan <- fqdn
		}
		close(processedDomainsChan)
		log.Println("Async domain processor finished feeding all domains.")
	}(allInputDomains)

	initialQueueCapacity := config.MaxBatchSize * 4
	if initialQueueCapacity < 2048 {
		initialQueueCapacity = 2048
	}
	packetQueue := make(chan PacketInfo, initialQueueCapacity)
	log.Printf("Packet queue capacity: %d", initialQueueCapacity)

	stopStats := make(chan struct{})
	programDone := make(chan struct{})
	var senderWg sync.WaitGroup
	statsUpdateChan := make(chan StatsUpdateData, 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start bottleneck reporter if in verbose mode
	var reporterWg sync.WaitGroup
	if config.Verbose {
		reporterWg.Add(1)
		go func() {
			defer reporterWg.Done()
			bottleneckReporter(ctx, config)
		}()
	}

	go statsCollector(statsUpdateChan, stopStats, programDone, config)
	senderWg.Add(1)

	go packetSender(ctx, xsk, packetQueue, &senderWg, config, domainStates)

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

	packetTemplate, err := createPacketTemplate(srcIP, srcMAC, dstMAC, config)
	if err != nil {
		log.Fatalf("Failed to create packet template: %v", err)
	}

	startTime := time.Now()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var lastRawStats xdp.Stats
	domainsCurrentlyManaged := 0
	totalDomainsForStats := initialTotalDomains

loop:
	for {
		select {
		case <-shutdownChan:
			log.Println("Shutdown signal received by manager. Stopping loop.")
			break loop
		case count, ok := <-uniqueDomainCountChan:
			if ok {
				totalDomainsForStats = count
			}
			uniqueDomainCountChan = nil // Stop selecting on it so the case doesn't fire again
		case <-ticker.C:
			// The entire management logic now runs on a schedule instead of a busy-loop.
			pendingCount := checkAndRetryDomains(domainStates, packetQueue, packetTemplate, config, rng, &failedDomainsList)
			domainsCurrentlyManaged = pendingCount

			// Feed new domains from the async processor
			feedThreshold := config.MaxBatchSize
			if domainsCurrentlyManaged < feedThreshold && processedDomainsChan != nil {
				domainsToFeed := make([]string, 0, config.MaxBatchSize*2)
			batchFillLoop:
				for i := 0; i < config.MaxBatchSize*2; i++ {
					select {
					case fqdn, ok := <-processedDomainsChan:
						if !ok {
							processedDomainsChan = nil // sentinel for closed channel
							break batchFillLoop
						}
						domainsToFeed = append(domainsToFeed, fqdn)
					default:
						// Channel is empty for now, stop trying to fill the batch
						break batchFillLoop
					}
				}
				if len(domainsToFeed) > 0 {
					feedStart := time.Now()
					added := feedDomainsToQueue(domainsToFeed, packetQueue, domainStates, packetTemplate, config, rng)
					domainsCurrentlyManaged += added
					recordTiming("Manager_FeedQueue", time.Since(feedStart))
				}
			}

			statsStart := time.Now()
			lastRawStats = calculateAndSendStats(xsk, startTime, lastRawStats, totalDomainsForStats, domainsCurrentlyManaged, statsUpdateChan)
			recordTiming("Manager_CalculateStats", time.Since(statsStart))

			// Exit condition: domain processor is done and no domains are left in-flight.
			if processedDomainsChan == nil && domainsCurrentlyManaged == 0 {
				log.Printf("All domains processed and queue/retries are clear.")
				break loop
			}
		}
	}

	log.Println("Stopping packet sender via context cancellation...")
	cancel()
	senderWg.Wait()
	log.Println("Packet sender stopped.")
	if config.Verbose {
		reporterWg.Wait()
		log.Println("Bottleneck reporter stopped.")
	}

	log.Println("Closing packet queue...")
	close(packetQueue)

	log.Println("Stopping statistics collector...")
	close(stopStats)
	<-programDone
	log.Println("Statistics collector stopped.")

	if config.Verbose {
		log.Println("--- Final Performance Analysis ---")
		printPerformanceReport(config)
	}
	generateFinalReport(failedDomainsList, totalDomainsForStats, startTime, xsk, config)

	return nil
}

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
	Data  string `json:"Data"`
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

func prettifyDnsMsg(msg *dns.Msg) *PrettyDnsMsg {
	if msg == nil {
		return nil
	}

	pretty := &PrettyDnsMsg{
		TransactionID: msg.Id,
		MessageType:   "Query",
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
		Additional: make([]PrettyDnsAnswer, 0, len(msg.Extra)),
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
			return PrettyDnsAnswer{Name: ".", Type: "OPT"}
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
		if _, ok := rr.(*dns.OPT); !ok {
			pretty.Additional = append(pretty.Additional, mapRR(rr))
		}
	}

	filteredAnswers := make([]PrettyDnsAnswer, 0, len(pretty.Answers))
	for _, ans := range pretty.Answers {
		if ans.Name != "" || ans.Type != "" || ans.Class != "" || ans.Data != "" {
			filteredAnswers = append(filteredAnswers, ans)
		}
	}
	pretty.Answers = filteredAnswers

	filteredAuthority := make([]PrettyDnsAnswer, 0, len(pretty.Authority))
	for _, auth := range pretty.Authority {
		if auth.Name != "" || auth.Type != "" || auth.Class != "" || auth.Data != "" {
			filteredAuthority = append(filteredAuthority, auth)
		}
	}
	pretty.Authority = filteredAuthority
	return pretty
}

func saveCachePrettified(config *Config) {
	if config.OutputFile == "" {
		log.Println("No output file specified, skipping save.")
		return
	}

	log.Printf("Saving cached responses to %s...", config.OutputFile)
	file, err := os.Create(config.OutputFile)
	if err != nil {
		log.Printf("Error creating output file '%s': %v", config.OutputFile, err)
		return
	}
	defer file.Close()

	// Use a buffered writer for efficient I/O
	writer := bufio.NewWriterSize(file, 65536) // Increased buffer size
	defer writer.Flush()

	skipCodes := make(map[int]struct{})
	for _, code := range config.CodesToSkip {
		skipCodes[code] = struct{}{}
	}

	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}
	// Channels for distributing work and collecting results
	jobs := make(chan *dns.Msg, numWorkers*2)
	results := make(chan []byte, numWorkers*2)
	var wgWorkers sync.WaitGroup
	var wgWriter sync.WaitGroup

	var savedCount, skippedCount atomic.Int64 // Use atomic for concurrent updates

	// Start worker goroutines
	wgWorkers.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wgWorkers.Done()
			for msg := range jobs {
				if _, skip := skipCodes[msg.Rcode]; !skip {
					prettyMsg := prettifyDnsMsg(msg)
					jsonData, err := json.Marshal(prettyMsg)
					if err != nil {
						// Log marshalling errors but continue processing other messages
						// Find the domain name from the question section for logging
						domainName := "unknown"
						if len(msg.Question) > 0 {
							domainName = msg.Question[0].Name
						}
						log.Printf("Error marshalling JSON for domain %s: %v", domainName, err)
						continue // Skip sending this result
					}
					results <- jsonData // Send marshalled JSON to the writer channel
					savedCount.Add(1)
				} else {
					skippedCount.Add(1)
				}
			}
		}()
	}

	// Start the writer goroutine
	wgWriter.Add(1)
	go func() {
		defer wgWriter.Done()
		for jsonData := range results {
			_, err := writer.Write(jsonData)
			if err == nil {
				_, err = writer.WriteString("\n")
			}
			if err != nil {
				// Log write errors; potentially stop processing if disk is full, etc.
				// For now, just log the error and continue.
				log.Printf("Error writing to output file: %v", err)
				// Consider adding logic here to handle persistent write errors,
				// maybe by cancelling the context or signalling other goroutines.
			}
		}
	}()

	// Feed the jobs channel from the cache
	// Note: cache.ForEach might block if the jobs channel is full.
	// The iteration itself is sequential, but processing happens in parallel.
	cache.ForEach(func(domainKey string, responseMsg *dns.Msg) bool {
		if responseMsg != nil {
			jobs <- responseMsg // Send message to workers
		}
		return true // Continue iteration
	})

	// Close the jobs channel once all items from the cache are sent
	close(jobs)

	// Wait for all worker goroutines to finish
	wgWorkers.Wait()

	// Close the results channel once all workers are done
	close(results)

	// Wait for the writer goroutine to finish writing all results
	wgWriter.Wait()

	// Ensure the buffer is flushed before returning
	err = writer.Flush()
	if err != nil {
		log.Printf("Error flushing writer for output file '%s': %v", config.OutputFile, err)
	}

	log.Printf("Finished saving cache. Saved %d responses, skipped %d based on RCODE.", savedCount.Load(), skippedCount.Load())
}

func main() {

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

	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if config.NIC == "" {
		log.Fatal("Error: Network interface (-interface) is required")
	}

	if config.MaxBatchSize <= 0 {
		log.Fatal("Error: Max batch size (-maxbatch) must be positive")
	}

	shutdownChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v. Initiating graceful shutdown...", sig)
		close(shutdownChan)

		<-time.After(5 * time.Second)
		log.Println("Shutdown timeout reached. Forcing exit.")
		os.Exit(1)
	}()

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

	bpfExited := make(chan struct{})
	go func() {
		defer close(bpfExited)
		BpfReceiver(config)
		log.Println("BPF Receiver goroutine finished.")
	}()
	select {
	case <-startedBPF:
		log.Println("BPF receiver started successfully.")
	case <-time.After(5 * time.Second):
		log.Fatal("Error: Timed out waiting for BPF receiver to start.")
	}

	var domains []string
	if *domainsFile != "" {
		loadedDomains, err := readDomainsFromFile(*domainsFile)
		if err != nil {
			log.Fatalf("Error reading domains file '%s': %v", *domainsFile, err)
		}
		domains = loadedDomains
		log.Printf("Read %d lines from %s", len(domains), *domainsFile)
	} else if config.DomainName != "" {
		domains = []string{config.DomainName}
		log.Printf("Using single domain: %s", config.DomainName)
	} else {
		log.Fatal("Error: Must provide a domain via -domain or a list via -domains")
	}

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

	opts := &xdp.SocketOptions{
		NumFrames:              4096,
		FrameSize:              2048,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 2048,
		RxRingNumDescs:         64,
		TxRingNumDescs:         2048,
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

	log.Println("Starting packet transmission process...")
	err = transmitPackets(xsk, domains, config, shutdownChan)
	if err != nil {
		log.Printf("Transmission process encountered an error: %v", err)
	} else {
		log.Println("Transmission process completed.")
	}

	log.Println("Saving results from cache...")
	saveCachePrettified(config)

	log.Println("Signaling BPF receiver to stop...")
	close(stopper)
	log.Println("Waiting for BPF receiver to exit gracefully...")
	select {
	case <-bpfExited:
		log.Println("BPF receiver exited.")
	case <-time.After(5 * time.Second):
		log.Println("Warning: Timed out waiting for BPF receiver to exit.")
	}

	log.Println("PugDNS finished.")
}

// --- Performance Analysis Utilities ---

func recordTiming(name string, d time.Duration) {
	performanceMutex.Lock()
	total, ok := performanceTimings[name]
	if !ok {
		total = &atomic.Uint64{}
		performanceTimings[name] = total
	}
	count, ok := performanceCounts[name]
	if !ok {
		count = &atomic.Uint64{}
		performanceCounts[name] = count
	}
	performanceMutex.Unlock()

	total.Add(uint64(d.Nanoseconds()))
	count.Add(1)
}

func timeOperation(name string) func() {
	start := time.Now()
	return func() {
		recordTiming(name, time.Since(start))
	}
}

type performanceStat struct {
	Name       string
	TotalTime  time.Duration
	Count      uint64
	AvgTime    time.Duration
	Percentage float64
}

func printPerformanceReport(config *Config) {
	performanceMutex.Lock()
	timingsSnapshot := make(map[string]uint64)
	countsSnapshot := make(map[string]uint64)
	var totalTimeNs uint64

	for name, val := range performanceTimings {
		ns := val.Load()
		timingsSnapshot[name] = ns
		totalTimeNs += ns
	}
	for name, val := range performanceCounts {
		countsSnapshot[name] = val.Load()
	}
	performanceMutex.Unlock()

	if totalTimeNs == 0 {
		return
	}

	statsList := make([]performanceStat, 0, len(timingsSnapshot))
	for name, ns := range timingsSnapshot {
		count := countsSnapshot[name]
		if count == 0 {
			continue
		}
		statsList = append(statsList, performanceStat{
			Name:       name,
			TotalTime:  time.Duration(ns),
			Count:      count,
			AvgTime:    time.Duration(ns / count),
			Percentage: (float64(ns) / float64(totalTimeNs)) * 100,
		})
	}

	sort.Slice(statsList, func(i, j int) bool {
		return statsList[i].Percentage > statsList[j].Percentage
	})

	var report strings.Builder
	report.WriteString("\n")
	for _, stat := range statsList {
		report.WriteString(fmt.Sprintf("%-20s: %6.2f%% | Avg: %-15s | Calls: %d\n",
			stat.Name, stat.Percentage, stat.AvgTime, stat.Count))
	}
	log.Print(report.String())
}

func bottleneckReporter(ctx context.Context, config *Config) {
	if !config.Verbose {
		return
	}
	log.Println("Bottleneck reporter started.")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("--- Performance Analysis Tick ---")
			printPerformanceReport(config)
		}
	}
}
