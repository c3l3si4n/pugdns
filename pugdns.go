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
)

type PacketInfo struct {
	Domain      string
	PacketBytes []byte
	Attempt     int
}

type DomainStatus struct {
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

var receivedPackets uint64
var statsPacketSentAttempted uint64
var totalDomainsProcessed uint64

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
		if line != "" && !strings.HasPrefix(line, "#") {
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

func prepareSinglePacket(fqdn string, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, config *Config, rng *rand.Rand) (PacketInfo, error) {
	if len(config.Nameservers) == 0 {
		return PacketInfo{}, fmt.Errorf("no nameservers configured for %s", fqdn)
	}

	currentNameserver := config.Nameservers[rng.Intn(len(config.Nameservers))]
	dstIP := net.ParseIP(currentNameserver)
	if dstIP == nil {
		return PacketInfo{}, fmt.Errorf("invalid nameserver IP %s for %s", currentNameserver, fqdn)
	}
	dstIP = dstIP.To4()
	if dstIP == nil {
		return PacketInfo{}, fmt.Errorf("nameserver IP %s is not a valid IPv4 address for %s", currentNameserver, fqdn)
	}

	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64, Id: uint16(rng.Intn(65535)), Protocol: layers.IPProtocolUDP,
		SrcIP: srcIP, DstIP: dstIP, Flags: layers.IPv4DontFragment,
	}

	srcPort := layers.UDPPort(1024 + rng.Intn(65535-1024))
	udp := &layers.UDP{SrcPort: srcPort, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)

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

func packetSender(ctx context.Context, xsk *xdp.Socket, packetQueue <-chan PacketInfo, wg *sync.WaitGroup, config *Config, domainStates map[string]*DomainStatus,
	domainStatesMutex *sync.Mutex) {
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

		freeSlots := xsk.NumFreeTxSlots()
		if freeSlots == 0 {

			_, _, pollErr = xsk.Poll(pollTimeout)
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

		descsToRequest := freeSlots
		if descsToRequest > maxBatchSize {
			descsToRequest = maxBatchSize
		}
		if descsToRequest == 0 {
			runtime.Gosched()
			continue
		}

		descs := xsk.GetDescs(descsToRequest, false)
		if len(descs) == 0 {

			runtime.Gosched()
			continue
		}

		packetsToSend := make([]PacketInfo, 0, len(descs))
		descsFilled := 0

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

		if descsFilled > 0 {

			now := time.Now()
			domainStatesMutex.Lock()
			maxRetries := config.Retries + 1
			for _, pktInfo := range packetsToSend {
				if status, ok := domainStates[pktInfo.Domain]; ok {

					if !status.Responded && status.AttemptsMade < maxRetries {

						status.LastAttempt = now
					}
				} else {

				}
			}
			domainStatesMutex.Unlock()

			numSubmitted := xsk.Transmit(descs[:descsFilled])
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
	ticker := time.NewTicker(500 * time.Millisecond)
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

func feedDomainsToQueue(domainsToFeed []string, packetQueue chan<- PacketInfo, domainStates map[string]*DomainStatus, domainStatesMutex *sync.Mutex, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, config *Config, rng *rand.Rand) int {
	if config.Verbose {
		log.Printf("Feeding batch of %d domains...", len(domainsToFeed))
	}
	addedAndQueued := 0
	now := time.Now()

	for _, fqdn := range domainsToFeed {

		pktInfo, err := prepareSinglePacket(fqdn, srcIP, srcMAC, dstMAC, config, rng)
		if err != nil {
			log.Printf("Error preparing initial packet for %s: %v. Skipping this domain.", fqdn, err)
			atomic.AddUint64(&totalDomainsProcessed, 1)
			continue
		}
		pktInfo.Attempt = 1

		select {
		case packetQueue <- pktInfo:

			domainStatesMutex.Lock()

			if _, exists := domainStates[fqdn]; !exists {
				domainStates[fqdn] = &DomainStatus{
					AttemptsMade: 1,
					Responded:    false,
					LastAttempt:  now,
				}
				addedAndQueued++
			} else {

				log.Printf("Warning: Domain %s already exists in state map during initial feed.", fqdn)
			}
			domainStatesMutex.Unlock()
		default:
			log.Printf("Warning: Packet queue full during initial feed for %s. Domain will not be processed.", fqdn)

			atomic.AddUint64(&totalDomainsProcessed, 1)

		}
	}
	if config.Verbose {
		log.Printf("Fed batch complete. Added/Queued %d domains.", addedAndQueued)
	}
	return addedAndQueued
}

func checkAndRetryDomains(domainStates map[string]*DomainStatus, domainStatesMutex *sync.Mutex, packetQueue chan<- PacketInfo, srcIP net.IP, srcMAC, dstMAC net.HardwareAddr, config *Config, rng *rand.Rand, failedDomainsList *[]string) (pendingCount int) {

	now := time.Now()
	domainsToRetry := []string{}
	domainsToRemove := []string{}
	maxRetries := config.Retries + 1

	domainStatesMutex.Lock()
	for fqdn, status := range domainStates {

		if !status.Responded {
			if _, found := cache.Get(fqdn); found {
				if config.Verbose {
					log.Printf("Domain %s marked as responded based on cache check.", fqdn)
				}
				status.Responded = true
			}
		}

		if status.Responded {
			domainsToRemove = append(domainsToRemove, fqdn)
			atomic.AddUint64(&totalDomainsProcessed, 1)
			continue
		} else if status.AttemptsMade >= maxRetries {
			domainsToRemove = append(domainsToRemove, fqdn)
			*failedDomainsList = append(*failedDomainsList, fqdn)
			atomic.AddUint64(&totalDomainsProcessed, 1)
			continue
		}

		if !status.LastAttempt.IsZero() && now.Sub(status.LastAttempt) > config.RetryTimeout {

			domainsToRetry = append(domainsToRetry, fqdn)
			if config.Verbose {

			}
		} else if !status.LastAttempt.IsZero() {

			pendingCount++
		} else {

			log.Printf("Warning: Domain %s in unexpected state (pending, no LastAttempt). Adding to retry.", fqdn)
			domainsToRetry = append(domainsToRetry, fqdn)
		}
	}

	for _, fqdn := range domainsToRemove {
		delete(domainStates, fqdn)
	}
	domainStatesMutex.Unlock()

	queuedCount := 0
	failedToPrepareCount := 0
	retryLaterCount := 0

	if len(domainsToRetry) > 0 {
		if config.Verbose {

		}
		for _, fqdn := range domainsToRetry {

			var currentAttempt int
			var exists bool
			domainStatesMutex.Lock()
			status, exists := domainStates[fqdn]

			if !exists || status.Responded || status.AttemptsMade >= maxRetries {
				domainStatesMutex.Unlock()

				continue
			}
			currentAttempt = status.AttemptsMade
			domainStatesMutex.Unlock()

			pktInfo, err := prepareSinglePacket(fqdn, srcIP, srcMAC, dstMAC, config, rng)
			if err != nil {
				log.Printf("Error preparing retry packet for %s (attempt %d): %v. Marking failed.", fqdn, currentAttempt+1, err)
				failedToPrepareCount++

				domainStatesMutex.Lock()
				if status, ok := domainStates[fqdn]; ok {

					if !status.Responded && status.AttemptsMade < maxRetries {
						status.AttemptsMade = maxRetries
						*failedDomainsList = append(*failedDomainsList, fqdn)
						atomic.AddUint64(&totalDomainsProcessed, 1)
						delete(domainStates, fqdn)
					}
				}
				domainStatesMutex.Unlock()
				continue
			}

			pktInfo.Attempt = currentAttempt + 1

			select {
			case packetQueue <- pktInfo:
				queuedCount++

				domainStatesMutex.Lock()

				status, exists := domainStates[fqdn]
				if exists && !status.Responded && status.AttemptsMade < maxRetries {

					status.AttemptsMade++
					status.LastAttempt = time.Now()
				} else if exists {

				}
				domainStatesMutex.Unlock()
			default:

				retryLaterCount++
				if config.Verbose {

				}

			}
		}
		if config.Verbose && (queuedCount > 0 || failedToPrepareCount > 0 || retryLaterCount > 0) {

		}
	}

	domainStatesMutex.Lock()
	finalPendingCount := len(domainStates)
	domainStatesMutex.Unlock()

	return finalPendingCount
}

func transmitPackets(xsk *xdp.Socket, allInputDomains []string, config *Config, shutdownChan <-chan struct{}) error {

	domainStates := make(map[string]*DomainStatus)
	var domainStatesMutex sync.Mutex
	var failedDomainsList []string

	totalDomainsInFile := len(allInputDomains)
	if totalDomainsInFile == 0 {
		log.Println("No domains to process.")
		return nil
	}
	log.Printf("Loaded %d domains for processing.", totalDomainsInFile)
	atomic.StoreUint64(&totalDomainsProcessed, 0)

	log.Println("Preparing and deduplicating FQDNs...")
	numWorkers := runtime.NumCPU()
	if numWorkers > len(allInputDomains)/1000 && len(allInputDomains) > 1000 {
		numWorkers = len(allInputDomains) / 1000
	}
	if numWorkers == 0 {
		numWorkers = 1
	}
	fqdnChan := make(chan string, len(allInputDomains))
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

	chunkSize := (len(allInputDomains) + numWorkers - 1) / numWorkers
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(allInputDomains) {
			end = len(allInputDomains)
		}
		if start >= end {
			wg.Done()
			continue
		}
		go processChunk(allInputDomains[start:end])
	}

	go func() {
		wg.Wait()
		close(fqdnChan)
	}()

	uniqueFqdns := make(map[string]struct{})
	for fqdn := range fqdnChan {
		uniqueFqdns[fqdn] = struct{}{}
	}

	fqdnDomains := make([]string, 0, len(uniqueFqdns))
	for fqdn := range uniqueFqdns {
		fqdnDomains = append(fqdnDomains, fqdn)
	}

	totalDomainsInFile = len(fqdnDomains)
	log.Printf("Processing %d unique FQDN domains.", totalDomainsInFile)

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

	go statsCollector(statsUpdateChan, stopStats, programDone, config)
	senderWg.Add(1)

	go packetSender(ctx, xsk, packetQueue, &senderWg, config, domainStates, &domainStatesMutex)

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

	startTime := time.Now()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	var lastRawStats xdp.Stats
	nextDomainIndex := 0
	domainsCurrentlyManaged := 0

	initialBatchSize := config.MaxBatchSize * 2
	if initialBatchSize > len(fqdnDomains) {
		initialBatchSize = len(fqdnDomains)
	}
	if initialBatchSize > 0 {
		domainsToFeed := fqdnDomains[0:initialBatchSize]
		added := feedDomainsToQueue(domainsToFeed, packetQueue, domainStates, &domainStatesMutex, srcIP, srcMAC, dstMAC, config, rng)
		domainsCurrentlyManaged += added
		nextDomainIndex = initialBatchSize
	}

loop:
	for {

		pendingCount := checkAndRetryDomains(domainStates, &domainStatesMutex, packetQueue, srcIP, srcMAC, dstMAC, config, rng, &failedDomainsList)
		domainsCurrentlyManaged = pendingCount

		feedThreshold := config.MaxBatchSize
		if domainsCurrentlyManaged < feedThreshold && nextDomainIndex < totalDomainsInFile {
			batchEndIndex := nextDomainIndex + config.MaxBatchSize*2
			if batchEndIndex > totalDomainsInFile {
				batchEndIndex = totalDomainsInFile
			}
			if nextDomainIndex < batchEndIndex {
				domainsToFeed := fqdnDomains[nextDomainIndex:batchEndIndex]
				added := feedDomainsToQueue(domainsToFeed, packetQueue, domainStates, &domainStatesMutex, srcIP, srcMAC, dstMAC, config, rng)
				domainsCurrentlyManaged += added
				nextDomainIndex = batchEndIndex
			}
		}

		currentProcessed := atomic.LoadUint64(&totalDomainsProcessed)
		lastRawStats = calculateAndSendStats(xsk, startTime, lastRawStats, totalDomainsInFile, domainsCurrentlyManaged, statsUpdateChan)

		if int(currentProcessed) >= totalDomainsInFile && domainsCurrentlyManaged == 0 {

			log.Printf("All %d domains processed and queue/retries are clear.", totalDomainsInFile)
			break loop
		}

		select {
		case <-shutdownChan:
			log.Println("Shutdown signal received by manager. Stopping loop.")
			break loop
		case <-ticker.C:

			if config.Verbose {

			}
			continue
		default:

			runtime.Gosched()
		}
	}

	time.Sleep(2 * time.Second)

	log.Println("Stopping packet sender via context cancellation...")
	cancel()
	senderWg.Wait()
	log.Println("Packet sender stopped.")

	log.Println("Closing packet queue...")
	close(packetQueue)

	log.Println("Stopping statistics collector...")
	close(stopStats)
	<-programDone
	log.Println("Statistics collector stopped.")

	generateFinalReport(failedDomainsList, totalDomainsInFile, startTime, xsk, config)

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

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	skipCodes := make(map[int]struct{})
	for _, code := range config.CodesToSkip {
		skipCodes[code] = struct{}{}
	}

	savedCount := 0
	skippedCount := 0

	cache.ForEach(func(domainKey string, responseMsg *dns.Msg) bool {
		if responseMsg != nil {
			if _, skip := skipCodes[responseMsg.Rcode]; !skip {
				prettyMsg := prettifyDnsMsg(responseMsg)
				jsonData, err := json.Marshal(prettyMsg)
				if err != nil {
					log.Printf("Error marshalling JSON for domain %s: %v", domainKey, err)
					return true
				}
				_, err = writer.Write(jsonData)
				if err == nil {
					_, err = writer.WriteString("\n")
				}
				if err != nil {
					log.Printf("Error writing to output file for domain %s: %v", domainKey, err)

					return true
				}
				savedCount++
			} else {
				skippedCount++
			}
		}
		return true
	})

	log.Printf("Finished saving cache. Saved %d responses, skipped %d based on RCODE.", savedCount, skippedCount)
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
