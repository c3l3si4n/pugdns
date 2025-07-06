package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
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

	"io"

	"github.com/slavc/xdp"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/rand"
	"golang.org/x/sys/unix"
)

// Version information
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
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
	TotalDomains             int
	RespondedDomains         int
	RetryingDomains          int
	FailedDomains            int
	ReceivedPackets          uint64
	PacketsSentRaw           uint64
	PacketsPerSecRaw         uint64
	AvgPacketsPerSecRaw      float64
	SmoothedPacketsPerSecRaw float64
	Duration                 float64
}

// Performance-related globals
var (
	performanceTimings = make(map[string]*atomic.Uint64)
	performanceCounts  = make(map[string]*atomic.Uint64)
	performanceMutex   sync.Mutex
)

// ShardedHaxMap provides a sharded cache to reduce lock contention.
type ShardedHaxMap struct {
	shards    []*haxmap.Map[string, []byte]
	numShards uint32
}

// NewShardedHaxMap creates and initializes a new sharded map.
func NewShardedHaxMap(numShards uint32) *ShardedHaxMap {
	if numShards == 0 {
		numShards = 1
	}
	shm := &ShardedHaxMap{
		shards:    make([]*haxmap.Map[string, []byte], numShards),
		numShards: numShards,
	}
	for i := uint32(0); i < numShards; i++ {
		shm.shards[i] = haxmap.New[string, []byte]()
	}
	return shm
}

func (shm *ShardedHaxMap) getShardIndex(key string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(key))
	return h.Sum32() % shm.numShards
}

// Set adds a key-value pair to the appropriate shard.
func (shm *ShardedHaxMap) Set(key string, value []byte) {
	shardIndex := shm.getShardIndex(key)
	shm.shards[shardIndex].Set(key, value)
}

// Get retrieves a value from the appropriate shard.
func (shm *ShardedHaxMap) Get(key string) ([]byte, bool) {
	shardIndex := shm.getShardIndex(key)
	return shm.shards[shardIndex].Get(key)
}

// Del removes a key from the appropriate shard.
func (shm *ShardedHaxMap) Del(key string) {
	shardIndex := shm.getShardIndex(key)
	shm.shards[shardIndex].Del(key)
}

// ForEach iterates over all key-value pairs in all shards.
func (shm *ShardedHaxMap) ForEach(f func(string, []byte) bool) {
	for _, shard := range shm.shards {
		cont := true
		shard.ForEach(func(key string, val []byte) bool {
			cont = f(key, val)
			return cont
		})
		if !cont {
			break
		}
	}
}

// Len returns the total number of items across all shards.
func (shm *ShardedHaxMap) Len() int {
	var total int
	for _, shard := range shm.shards {
		total += int(shard.Len())
	}
	return total
}

var receivedPackets uint64
var totalDomainsProcessed uint64
var totalUniqueDomains uint64
var respondedDomainsCount uint64

// Add new metrics for retry tracking
var domainsRequiringRetries uint64
var totalRetryAttempts uint64
var firstAttemptSuccesses uint64

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

func streamDomainsFromFile(filename string, domainChan chan<- string) {
	defer close(domainChan)

	file, err := os.Open(filename)
	if err != nil {
		appLogger.Fatal("Error opening domain file '%s' for streaming: %v", filename, err)
		return
	}
	defer file.Close()

	const maxChunkSize = 4 * 1024 * 1024 // 4MB chunks
	reader := bufio.NewReaderSize(file, maxChunkSize)
	var remainder []byte

	for {
		chunk := make([]byte, maxChunkSize)
		bytesRead, readErr := reader.Read(chunk)

		if bytesRead > 0 {
			// Prepend remainder from the previous chunk to form the current working data.
			currentData := append(remainder, chunk[:bytesRead]...)
			lastNewline := bytes.LastIndexByte(currentData, '\n')

			if lastNewline != -1 {
				// Process all complete lines found in the current data.
				lines := bytes.Split(currentData[:lastNewline], []byte{'\n'})
				for _, line := range lines {
					trimmed := bytes.TrimSpace(line)
					if len(trimmed) > 0 {
						domainChan <- string(trimmed)
					}
				}
				// Save the potentially incomplete line after the last newline for the next iteration.
				// A copy is made to prevent aliasing the chunk buffer.
				newRemainder := make([]byte, len(currentData)-lastNewline-1)
				copy(newRemainder, currentData[lastNewline+1:])
				remainder = newRemainder
			} else {
				// No newline was found in the entire chunk, so the whole thing is a remainder.
				// A copy is made to prevent aliasing the chunk buffer.
				newRemainder := make([]byte, len(currentData))
				copy(newRemainder, currentData)
				remainder = newRemainder
			}
		}

		if readErr == io.EOF {
			// The file has been fully read. Process the final remainder, which contains
			// the last line if the file didn't end with a newline.
			if len(remainder) > 0 {
				trimmed := bytes.TrimSpace(remainder)
				if len(trimmed) > 0 {
					domainChan <- string(trimmed)
				}
			}
			break // Exit the loop
		}

		if readErr != nil {
			appLogger.Warn("Error reading chunk from domain file: %v", readErr)
			break // Exit on other errors
		}
	}
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

	// 2. Create the final packet from template and payload.
	// Simple allocation is cleaner and avoids the complexity and bugs of sync.Pool.
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
	appLogger.Info("Packet sender started.")

	maxBatchSize := config.MaxBatchSize
	pollTimeout := config.PollTimeoutMs

	for {

		_, _, pollErr := xsk.Poll(0)
		if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR && pollErr != unix.EAGAIN {
			appLogger.Warn("Sender Poll error: %v", pollErr)
		} else {
			numCompleted := xsk.NumCompleted()
			if numCompleted > 0 {
				xsk.Complete(numCompleted)
			}
		}

		select {
		case <-ctx.Done():
			appLogger.Info("Packet sender received stop signal. Finalizing...")
			finalizeTransmission(xsk, config)
			appLogger.Success("Packet sender finished.")
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
				appLogger.Warn("Sender Poll(timeout) error: %v", pollErr)
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
					appLogger.Warn("Packet queue closed. Sender stopping fill loop.")
					break fillLoop
				}
				if len(pktInfo.PacketBytes) == 0 {
					appLogger.Warn("Empty packet bytes for domain %s", pktInfo.Domain)
					continue
				}

				frame := xsk.GetFrame(descs[descsFilled])
				if len(frame) < len(pktInfo.PacketBytes) {
					appLogger.Error("Frame size (%d) too small for packet (%d bytes) for domain %s. Skipping.", len(frame), len(pktInfo.PacketBytes), pktInfo.Domain)
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

			if numSubmitted < descsFilled {
				appLogger.Warn("Sender failed to submit %d packets (%d/%d). Manager will retry.", descsFilled-numSubmitted, numSubmitted, descsFilled)
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
		appLogger.Info("Starting transmission finalization...")
	}
	startTime := time.Now()
	timeout := 1000 * time.Millisecond

	for time.Since(startTime) < timeout {
		numTransmitting := xsk.NumTransmitted()
		if numTransmitting == 0 {
			if config.Verbose {
				appLogger.Info("Finalization: No packets transmitting after %.2fs.", time.Since(startTime).Seconds())
			}
			break
		}

		_, _, pollErr := xsk.Poll(20)
		if pollErr != nil && pollErr != unix.ETIMEDOUT && pollErr != unix.EINTR {
			appLogger.Warn("Final poll error: %v", pollErr)
		}

		completed := xsk.NumCompleted()
		if completed > 0 {
			xsk.Complete(completed)
			if config.Verbose {
				appLogger.Info("Finalization: Completed %d packets", completed)
			}

		} else if pollErr == unix.ETIMEDOUT || pollErr == unix.EINTR || pollErr == nil {
			runtime.Gosched()
		} else {
			break
		}
	}

	finalNumTransmitting := xsk.NumTransmitted()
	if finalNumTransmitting > 0 {
		appLogger.Warn("Finalization finished, but %d packets still marked as transmitting.", finalNumTransmitting)
	} else if config.Verbose {
		appLogger.Success("Finalization complete.")
	}
}

func statsCollector(updateChan <-chan StatsUpdateData, stopStats <-chan struct{}, programDone chan<- struct{}, config *Config, progressDisplay *ProgressDisplay) {
	if !config.Quiet {
		appLogger.Info("Statistics collector started.")
	}

	var lastUpdate StatsUpdateData
	statsInterval, _ := time.ParseDuration(config.StatsInterval)
	if statsInterval <= 0 {
		statsInterval = 2 * time.Second
	}
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()
	running := true

	if progressDisplay != nil && !config.Quiet {
		progressDisplay.Start()
	}

	for running {
		select {
		case updateData, ok := <-updateChan:
			if !ok {
				running = false
				break
			}
			lastUpdate = updateData

		case <-ticker.C:
			if lastUpdate.TotalDomains > 0 && progressDisplay != nil && !config.Quiet {
				queueSize := int64(lastUpdate.RetryingDomains)
				progressDisplay.Update(
					int64(lastUpdate.RespondedDomains),
					int64(lastUpdate.FailedDomains),
					int64(lastUpdate.RetryingDomains),
					lastUpdate.PacketsSentRaw,
					lastUpdate.ReceivedPackets,
					queueSize,
					lastUpdate.SmoothedPacketsPerSecRaw,
				)
			}

		case <-stopStats:
			running = false
			break
		}
	}

	if progressDisplay != nil {
		progressDisplay.Stop()
	}

	if !config.Quiet {
		fmt.Println()
		appLogger.Info("Statistics collector shutting down.")

		if lastUpdate.TotalDomains > 0 {
			prog := float64(lastUpdate.RespondedDomains+lastUpdate.FailedDomains) / float64(lastUpdate.TotalDomains) * 100
			statsLine := fmt.Sprintf("Final Stats: D:%d | Rsp:%d | Fail:%d | Pend:%d | Rx:%d | RawTX:%d | RawRate:%d pps | RawAvg:%.1f pps | Time:%.1fs | Prog:%.1f%%",
				lastUpdate.TotalDomains, lastUpdate.RespondedDomains, lastUpdate.FailedDomains, lastUpdate.RetryingDomains,
				lastUpdate.ReceivedPackets, lastUpdate.PacketsSentRaw, lastUpdate.PacketsPerSecRaw,
				lastUpdate.AvgPacketsPerSecRaw, lastUpdate.Duration, prog)
			appLogger.Info(statsLine)
		}
	}
	programDone <- struct{}{}
}

func calculateAndSendStats(xsk *xdp.Socket, startTime time.Time, lastRawStats xdp.Stats, lastStatsTime time.Time, smoothedPPS float64, totalDomainsInFile int, domainsCurrentlyManaged int, statsUpdateChan chan<- StatsUpdateData) (xdp.Stats, time.Time, float64) {
	now := time.Now()
	duration := now.Sub(startTime).Seconds()
	currentReceived := atomic.LoadUint64(&receivedPackets)
	curProcessed := atomic.LoadUint64(&totalDomainsProcessed)
	curResponded := atomic.LoadUint64(&respondedDomainsCount)
	curRawStats, _ := xsk.Stats()

	intervalPacketsRaw := curRawStats.Completed - lastRawStats.Completed

	intervalSeconds := now.Sub(lastStatsTime).Seconds()
	intervalRateRaw := uint64(0)
	if intervalSeconds > 0 {
		intervalRateRaw = uint64(float64(intervalPacketsRaw) / intervalSeconds)
	}
	avgRateRaw := 0.0
	if duration > 0 {
		avgRateRaw = float64(curRawStats.Completed) / duration
	}

	const smoothingFactor = 0.1 // Adjust for more or less smoothing
	newSmoothedPPS := (float64(intervalRateRaw) * smoothingFactor) + (smoothedPPS * (1 - smoothingFactor))

	finalRespondedApprox := int(curResponded)
	finalFailedApprox := int(curProcessed) - finalRespondedApprox
	if finalFailedApprox < 0 {
		finalFailedApprox = 0
	}

	updateData := StatsUpdateData{
		TotalDomains:             totalDomainsInFile,
		RespondedDomains:         finalRespondedApprox,
		RetryingDomains:          domainsCurrentlyManaged,
		FailedDomains:            finalFailedApprox,
		ReceivedPackets:          currentReceived,
		PacketsSentRaw:           curRawStats.Completed,
		PacketsPerSecRaw:         intervalRateRaw,
		AvgPacketsPerSecRaw:      avgRateRaw,
		SmoothedPacketsPerSecRaw: newSmoothedPPS,
		Duration:                 duration,
	}

	select {
	case statsUpdateChan <- updateData:
	default:
	}

	return curRawStats, now, newSmoothedPPS
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

func feedDomainsToQueue(domainsToFeed []string, packetQueue chan<- PacketInfo, domainStates *haxmap.Map[string, *DomainStatus], processedHistory *haxmap.Map[string, struct{}], packetTemplate []byte, config *Config, rng *rand.Rand, errorGrouper *ErrorGrouper) int {
	if config.Verbose {
		appLogger.Debug("Feeding batch of %d domains...", len(domainsToFeed))
	}
	addedAndQueued := 0
	now := time.Now()

	for _, fqdn := range domainsToFeed {
		// Full deduplication against all domains ever queued using the new history map.
		if _, loaded := processedHistory.GetOrSet(fqdn, struct{}{}); loaded {
			continue // Domain already seen, skip.
		}

		// If we are here, it's a new, unique domain.
		atomic.AddUint64(&totalUniqueDomains, 1)

		// Set initial state for in-flight tracking.
		domainStates.Set(fqdn, &DomainStatus{
			AttemptsMade: 1,
			Responded:    false,
			LastAttempt:  now,
		})

		if len(config.Nameservers) == 0 {
			err := fmt.Errorf("no nameservers configured")
			errorGrouper.RecordError(err, fqdn)
			if config.Verbose {
				appLogger.Error("Error preparing packet for %s: No nameservers configured. Skipping this domain.", fqdn)
			}
			atomic.AddUint64(&totalDomainsProcessed, 1)
			domainStates.Del(fqdn) // Clean up state for skipped domain
			continue
		}
		currentNameserver := config.Nameservers[rng.Intn(len(config.Nameservers))]
		dstIP := net.ParseIP(currentNameserver)
		if dstIP == nil {
			err := fmt.Errorf("invalid nameserver IP: %s", currentNameserver)
			errorGrouper.RecordError(err, fqdn)
			if config.Verbose {
				appLogger.Error("Error preparing packet for %s: Invalid nameserver IP %s. Skipping this domain.", fqdn, currentNameserver)
			}
			atomic.AddUint64(&totalDomainsProcessed, 1)
			domainStates.Del(fqdn) // Clean up state for skipped domain
			continue
		}

		packetBytes, err := prepareSinglePacket(packetTemplate, fqdn, dstIP, rng)
		if err != nil {
			errorGrouper.RecordError(err, fqdn)
			if config.Verbose {
				appLogger.Error("Error preparing initial packet for %s: %v. Skipping this domain.", fqdn, err)
			}
			atomic.AddUint64(&totalDomainsProcessed, 1)
			domainStates.Del(fqdn) // Clean up state for skipped domain
			continue
		}
		pktInfo := PacketInfo{Domain: fqdn, PacketBytes: packetBytes, Attempt: 1}
		addedAndQueued++
		packetQueue <- pktInfo
	}
	if config.Verbose {
		appLogger.Debug("Fed batch complete. Added/Queued %d domains.", addedAndQueued)
	}
	return addedAndQueued
}

func runAsyncResultWriter(config *Config) (chan<- []byte, func() (int64, int64, int64)) {
	if config.OutputFile == "" {
		// Return a dummy channel and a no-op closer if no output file is specified.
		dummyChan := make(chan []byte)
		go func() {
			for range dummyChan {
			}
		}()
		return dummyChan, func() (int64, int64, int64) {
			close(dummyChan)
			return 0, 0, 0
		}
	}

	// This channel receives the raw DNS payloads from the main manager loop.
	payloadChan := make(chan []byte, 16384)

	// This channel receives the marshalled JSON data from the parsing workers.
	jsonChan := make(chan []byte, 16384)

	var wgParser sync.WaitGroup
	var wgWriter sync.WaitGroup

	numWorkers := runtime.NumCPU()
	if numWorkers < 1 {
		numWorkers = 1
	}

	var savedCount, skippedCount, errorCount atomic.Int64

	// Start Parser Workers to parallelize the CPU-intensive work (unpack/marshal)
	wgParser.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func() {
			defer wgParser.Done()
			skipCodes := make(map[int]struct{})
			for _, code := range config.CodesToSkip {
				skipCodes[code] = struct{}{}
			}

			for payload := range payloadChan {
				msg := new(dns.Msg)
				if err := msg.Unpack(payload); err != nil {
					errorCount.Add(1)
					continue
				}

				if _, skip := skipCodes[msg.Rcode]; !skip {
					prettyMsg := prettifyDnsMsg(msg)
					jsonData, err := json.Marshal(prettyMsg)
					if err != nil {
						errorCount.Add(1)
						continue
					}
					jsonChan <- jsonData
					savedCount.Add(1)
				} else {
					skippedCount.Add(1)
				}
			}
		}()
	}

	// Start a single File Writer Goroutine to serialize disk I/O
	wgWriter.Add(1)
	go func() {
		defer wgWriter.Done()
		appLogger.Info("Async result writer started. Saving to %s...", config.OutputFile)
		file, err := os.Create(config.OutputFile)
		if err != nil {
			appLogger.Fatal("Error creating output file '%s': %v. Writer will not run.", config.OutputFile, err)
			return
		}
		defer file.Close()

		writer := bufio.NewWriterSize(file, 65536)
		defer writer.Flush()

		for jsonData := range jsonChan {
			_, _ = writer.Write(jsonData)
			_, _ = writer.WriteString("\n")
		}
		appLogger.Success("Async result writer finished writing to file.")
	}()

	// The function to be called to gracefully shut everything down
	closeFn := func() (int64, int64, int64) {
		close(payloadChan) // 1. Signal parsers no more payloads are coming
		wgParser.Wait()    // 2. Wait for all parsers to finish
		close(jsonChan)    // 3. Signal writer no more JSON is coming
		wgWriter.Wait()    // 4. Wait for writer to finish
		appLogger.Info("Async result writer has shut down.")
		return savedCount.Load(), skippedCount.Load(), errorCount.Load()
	}

	// Return the channel that the main application will write payloads to
	return payloadChan, closeFn
}

func transmitPackets(xsk *xdp.Socket, domainsFile string, config *Config, shutdownChan <-chan struct{}, totalDomainsInFile int, errorGrouper *ErrorGrouper) error {

	processedHistory := haxmap.New[string, struct{}]()
	domainStates := haxmap.New[string, *DomainStatus]()
	var failedDomainsList []string

	atomic.StoreUint64(&totalDomainsProcessed, 0)
	atomic.StoreUint64(&totalUniqueDomains, 0)
	atomic.StoreUint64(&respondedDomainsCount, 0)
	atomic.StoreUint64(&domainsRequiringRetries, 0)
	atomic.StoreUint64(&totalRetryAttempts, 0)
	atomic.StoreUint64(&firstAttemptSuccesses, 0)

	// --- Channel for streaming domains from file ---
	processedDomainsChan := make(chan string, config.MaxBatchSize*4)

	// --- Start file streaming goroutine ---
	go func() {
		// Delay domain streaming slightly to allow progress display to initialize
		time.Sleep(100 * time.Millisecond)
		streamDomainsFromFile(domainsFile, processedDomainsChan)
	}()

	initialQueueCapacity := config.MaxBatchSize * 4
	if initialQueueCapacity < 2048 {
		initialQueueCapacity = 2048
	}
	packetQueue := make(chan PacketInfo, initialQueueCapacity)
	if !config.Quiet {
		appLogger.Info("Packet queue capacity: %d", initialQueueCapacity)
	}

	stopStats := make(chan struct{})
	programDone := make(chan struct{})
	var senderWg sync.WaitGroup
	statsUpdateChan := make(chan StatsUpdateData, 20)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create progress display
	var progressDisplay *ProgressDisplay
	if !config.Quiet {
		progressDisplay = NewProgressDisplay(int64(totalDomainsInFile))
	}

	// Start bottleneck reporter if in verbose mode
	var reporterWg sync.WaitGroup
	if config.Verbose {
		reporterWg.Add(1)
		go func() {
			defer reporterWg.Done()
			bottleneckReporter(ctx, config)
		}()
	}

	go statsCollector(statsUpdateChan, stopStats, programDone, config, progressDisplay)
	senderWg.Add(1)

	go packetSender(ctx, xsk, packetQueue, &senderWg, config, domainStates)

	// Start the async result writer
	writeChan, closeWriter := runAsyncResultWriter(config)

	rng := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
	link, err := netlink.LinkByName(config.NIC)
	if err != nil {
		appLogger.Fatal("Failed to get link by name: %v", err)
	}
	srcMAC, dstMAC, err := ResolveMACAddresses(config, link)
	if err != nil {
		appLogger.Fatal("Failed to resolve MAC addresses: %v", err)
	}
	srcIP := net.ParseIP(config.SrcIP)
	if srcIP == nil {
		appLogger.Fatal("Failed to parse source IP: %v", err)
	}

	packetTemplate, err := createPacketTemplate(srcIP, srcMAC, dstMAC, config)
	if err != nil {
		appLogger.Fatal("Failed to create packet template: %v", err)
	}

	startTime := time.Now()

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var lastRawStats xdp.Stats
	var lastStatsTime = startTime
	var smoothedPPS float64
	domainsCurrentlyManaged := 0
	noProgressTicks := 0
	const noProgressTimeoutTicks = 200 // 10 seconds at a 50ms tick rate

loop:
	for {
		select {
		case <-shutdownChan:
			appLogger.Warn("Shutdown signal received by manager. Stopping loop.")
			break loop
		case <-ticker.C:
			prevPending := domainsCurrentlyManaged
			// The entire management logic now runs on a schedule instead of a busy-loop.
			pendingCount := checkAndRetryDomains(ctx, domainStates, packetQueue, packetTemplate, config, rng, &failedDomainsList, writeChan, false)
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
							appLogger.Info("Domain streaming finished.")
							break batchFillLoop
						}
						// Normalize domain on the fly
						processedDomain := strings.TrimSpace(fqdn)
						if processedDomain != "" {
							if !strings.HasSuffix(processedDomain, ".") {
								processedDomain += "."
							}
							domainsToFeed = append(domainsToFeed, processedDomain)
						}
					default:
						// Channel is empty for now, stop trying to fill the batch
						break batchFillLoop
					}
				}
				if len(domainsToFeed) > 0 {
					feedStart := time.Now()
					added := feedDomainsToQueue(domainsToFeed, packetQueue, domainStates, processedHistory, packetTemplate, config, rng, errorGrouper)
					domainsCurrentlyManaged += added
					recordTiming("Manager_FeedQueue", time.Since(feedStart))
				}
			}

			statsStart := time.Now()
			lastRawStats, lastStatsTime, smoothedPPS = calculateAndSendStats(xsk, startTime, lastRawStats, lastStatsTime, smoothedPPS, totalDomainsInFile, domainsCurrentlyManaged, statsUpdateChan)
			recordTiming("Manager_CalculateStats", time.Since(statsStart))

			// Stalemate and exit condition logic
			if processedDomainsChan == nil {
				if domainsCurrentlyManaged == 0 {
					appLogger.Success("\nAll domains processed and queue/retries are clear.")
					break loop
				}

				// Check for stalemate
				if domainsCurrentlyManaged > 0 && domainsCurrentlyManaged == prevPending {
					noProgressTicks++
				} else {
					noProgressTicks = 0 // Progress was made, reset counter
				}

				if noProgressTicks > noProgressTimeoutTicks {
					appLogger.Warn("\nStalemate detected. Forcing exit with %d pending domains.", domainsCurrentlyManaged)
					domainStates.ForEach(func(fqdn string, status *DomainStatus) bool {
						failedDomainsList = append(failedDomainsList, fqdn)
						return true
					})
					break loop
				}
			}
		}
	}

	appLogger.Info("Manager loop finished. Draining final responses...")
	checkAndRetryDomains(ctx, domainStates, packetQueue, packetTemplate, config, rng, &failedDomainsList, writeChan, true)

	appLogger.Info("Stopping packet sender via context cancellation...")
	cancel()
	senderWg.Wait()
	appLogger.Success("Packet sender stopped.")
	if config.Verbose {
		reporterWg.Wait()
		appLogger.Info("Bottleneck reporter stopped.")
	}

	appLogger.Info("Closing packet queue...")
	close(packetQueue)

	appLogger.Info("Stopping statistics collector...")
	close(stopStats)
	<-programDone
	appLogger.Success("Statistics collector stopped.")

	appLogger.Info("Closing result writer and waiting for completion...")
	savedCount, skippedCount, errorCount := closeWriter()

	if config.Verbose {
		printPerformanceReport(config)
	}

	// --- Enhanced Final Summary ---
	if !config.Quiet {
		fmt.Println()
		fmt.Println(strings.Repeat("═", 60))
		appLogger.Success("📊 PugDNS Scan Report")
		fmt.Println(strings.Repeat("═", 60))

		// Results Summary
		fmt.Println()
		appLogger.Info("📈 Results Summary:")
		finalFailed := len(failedDomainsList)
		uniqueDomains := atomic.LoadUint64(&totalUniqueDomains)
		successRate := float64(savedCount) / float64(uniqueDomains) * 100

		appLogger.Info("  ├─ Total Domains: %s", formatNumber(int64(uniqueDomains)))
		appLogger.Info("  ├─ Successful: %s (%.1f%%)", formatNumber(savedCount), successRate)
		appLogger.Info("  ├─ Failed: %s (%.1f%%)", formatNumber(int64(finalFailed)), float64(finalFailed)/float64(uniqueDomains)*100)
		if skippedCount > 0 {
			appLogger.Info("  ├─ Filtered (RCODE): %s", formatNumber(skippedCount))
		}
		if errorCount > 0 {
			appLogger.Info("  └─ Write Errors: %s", formatNumber(errorCount))
		}

		// Performance Metrics
		fmt.Println()
		appLogger.Info("⚡ Performance Metrics:")
		totalRuntime := time.Since(startTime).Seconds()
		avgRate := float64(atomic.LoadUint64(&totalDomainsProcessed)) / totalRuntime
		finalSentXDP, _ := xsk.Stats()

		// Calculate packet efficiency - how many packets per domain on average
		avgPacketsPerDomain := float64(finalSentXDP.Completed) / float64(uniqueDomains)
		packetOverhead := ((float64(finalSentXDP.Completed) - float64(uniqueDomains)) / float64(uniqueDomains)) * 100

		appLogger.Info("  ├─ Total Runtime: %s", formatDuration(time.Since(startTime)))
		appLogger.Info("  ├─ Average Rate: %.0f queries/sec", avgRate)
		appLogger.Info("  ├─ Avg Packets/Domain: %.2f", avgPacketsPerDomain)
		appLogger.Info("  └─ Packet Overhead: %.1f%%", packetOverhead)

		// Query Efficiency Metrics
		fmt.Println()
		appLogger.Info("🎯 Query Efficiency:")
		finalFirstAttempts := atomic.LoadUint64(&firstAttemptSuccesses)
		finalDomainsNeedingRetries := atomic.LoadUint64(&domainsRequiringRetries)
		finalTotalRetries := atomic.LoadUint64(&totalRetryAttempts)

		firstAttemptRate := float64(finalFirstAttempts) / float64(uniqueDomains) * 100
		retryRate := float64(finalDomainsNeedingRetries) / float64(uniqueDomains) * 100

		appLogger.Info("  ├─ First-attempt Success: %.1f%% (%s/%s domains)",
			firstAttemptRate, formatNumber(int64(finalFirstAttempts)), formatNumber(int64(uniqueDomains)))
		appLogger.Info("  ├─ Domains Requiring Retries: %.1f%% (%s domains)",
			retryRate, formatNumber(int64(finalDomainsNeedingRetries)))
		appLogger.Info("  └─ Total Retry Attempts: %s", formatNumber(int64(finalTotalRetries)))

		// Network Statistics
		fmt.Println()
		appLogger.Info("🌐 Network Statistics:")
		finalReceived := atomic.LoadUint64(&receivedPackets)
		networkLoss := (1 - float64(finalReceived)/float64(finalSentXDP.Completed)) * 100
		appLogger.Info("  ├─ Packets Sent: %s", formatNumber(int64(finalSentXDP.Completed)))
		appLogger.Info("  ├─ Packets Received: %s", formatNumber(int64(finalReceived)))
		appLogger.Info("  └─ Network Packet Loss: %.2f%%", networkLoss)

		// Failed domains sample
		if finalFailed > 0 && config.Verbose {
			fmt.Println()
			appLogger.Warn("❌ Sample of failed domains (showing up to 10):")
			limit := 10
			if finalFailed < limit {
				limit = finalFailed
			}
			for i := 0; i < limit; i++ {
				appLogger.Info("  • %s", failedDomainsList[i])
			}
			if finalFailed > limit {
				appLogger.Info("  • ... and %d more", finalFailed-limit)
			}
		}

		fmt.Println(strings.Repeat("═", 60))
	}

	return nil
}

func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, fmt.Errorf("error opening file '%s' for counting: %w", filename, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Increase buffer size for scanner to handle long lines efficiently.
	const maxCapacity = 1024 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	count := 0
	for scanner.Scan() {
		// We only care about non-empty lines, to match the streaming logic.
		if len(bytes.TrimSpace(scanner.Bytes())) > 0 {
			count++
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("error scanning file '%s': %w", filename, err)
	}

	return count, nil
}

func main() {
	// Support environment variables
	if envInterface := os.Getenv("PUGDNS_INTERFACE"); envInterface != "" {
		os.Args = append(os.Args, "-interface", envInterface)
	}
	if envNameservers := os.Getenv("PUGDNS_NAMESERVERS"); envNameservers != "" {
		os.Args = append(os.Args, "-nameservers", envNameservers)
	}

	config := DefaultConfig()

	// File inputs
	domainsFile := flag.String("domains", "", "File containing domains to query (one per line)")
	nameserversFile := flag.String("nameservers", "", "File containing nameservers to use (one per line)")
	configFile := flag.String("config", "", "Configuration file (YAML or JSON)")

	// Operation modes
	showVersion := flag.Bool("version", false, "Show version information")
	generateConfig := flag.String("generate-config", "", "Generate example configuration file")
	pprofEnabled := flag.Bool("pprof", false, "Enable pprof debugging server on localhost:6060")
	flag.BoolVar(&config.DryRun, "dry-run", config.DryRun, "Validate configuration without sending packets")

	// Display options
	logLevel := flag.String("loglevel", "info", "Set log level (debug, info, warn, error)")
	flag.BoolVar(&config.Verbose, "verbose", config.Verbose, "Enable verbose logging")
	flag.BoolVar(&config.Quiet, "quiet", config.Quiet, "Suppress all output except errors and final summary")
	flag.StringVar(&config.StatsInterval, "stats-interval", config.StatsInterval, "Statistics update interval (e.g., 2s, 500ms)")

	// Network configuration
	flag.StringVar(&config.NIC, "interface", config.NIC, "Network interface")
	flag.IntVar(&config.QueueID, "queue", config.QueueID, "Interface queue ID")
	flag.StringVar(&config.SrcMAC, "srcmac", config.SrcMAC, "Source MAC (optional, uses interface MAC if empty)")
	flag.StringVar(&config.DstMAC, "dstmac", config.DstMAC, "Destination MAC (optional, resolves via ARP if empty)")
	flag.StringVar(&config.SrcIP, "srcip", config.SrcIP, "Source IP (optional, uses interface IP if empty)")

	// Query configuration
	flag.StringVar(&config.DomainName, "domain", config.DomainName, "Single domain to query (overridden by -domains)")
	flag.DurationVar(&config.RetryTimeout, "retry-timeout", config.RetryTimeout, "Retry timeout")
	flag.IntVar(&config.Retries, "retries", config.Retries, "Retries per domain")

	// Performance tuning
	flag.IntVar(&config.MaxBatchSize, "maxbatch", config.MaxBatchSize, "Max XDP TX batch size")
	flag.IntVar(&config.PollTimeoutMs, "poll", config.PollTimeoutMs, "XDP socket poll timeout (ms)")

	// Output configuration
	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "File to save results")

	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Printf("PugDNS version %s\nBuild time: %s\nGit commit: %s\n", Version, BuildTime, GitCommit)
		os.Exit(0)
	}

	// Handle generate-config flag
	if *generateConfig != "" {
		if err := GenerateExampleConfig(*generateConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating config file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Example configuration written to %s\n", *generateConfig)
		os.Exit(0)
	}

	// Load configuration from file if specified
	if *configFile != "" {
		fileConfig, err := LoadConfigFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
			os.Exit(1)
		}
		// Command-line flags override config file values
		savedFlags := *config
		*config = *fileConfig
		// Restore command-line overrides
		flag.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "interface":
				config.NIC = savedFlags.NIC
			case "verbose":
				config.Verbose = savedFlags.Verbose
			case "quiet":
				config.Quiet = savedFlags.Quiet
				// Add other overrides as needed
			}
		})
	}

	// Auto-discover interface if not specified
	if config.NIC == "" {
		appLogger.Info("Interface not specified, attempting to auto-discover...")
		discoveredInterface, err := findDefaultInterface()
		if err != nil {
			appLogger.Fatal("Failed to auto-discover interface: %v. Please specify one using the -interface flag.", err)
		}
		config.NIC = discoveredInterface
		appLogger.Success("✓ Discovered default interface: %s", config.NIC)
	}

	// Set log level and adjust for quiet mode
	appLogger.SetLevel(LogLevelFromString(*logLevel))
	if config.Quiet {
		appLogger.SetLevel(ERROR)
	}

	// Initialize the sharded cache here, before any goroutines start.
	cache = NewShardedHaxMap(uint32(runtime.NumCPU()))

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if *pprofEnabled {
		go func() {
			appLogger.Info("Starting pprof server on http://localhost:6060/debug/pprof")
			if err := http.ListenAndServe("localhost:6060", nil); err != nil {
				appLogger.Warn("Error starting pprof server: %v", err)
			}
		}()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		appLogger.Fatal("Configuration error: %v", err)
	}

	// Perform dry-run checks if requested
	if config.DryRun {
		appLogger.Info("🔍 Running in dry-run mode - validating configuration...")

		// Check interface exists
		if _, err := netlink.LinkByName(config.NIC); err != nil {
			appLogger.Error("Interface check failed: %v", err)
			os.Exit(1)
		}
		appLogger.Success("✓ Network interface '%s' exists", config.NIC)

		// Check domain file if specified
		if *domainsFile != "" {
			if _, err := os.Stat(*domainsFile); err != nil {
				appLogger.Error("Domain file check failed: %v", err)
				os.Exit(1)
			}
			count, err := countLines(*domainsFile)
			if err != nil {
				appLogger.Error("Failed to count domains: %v", err)
				os.Exit(1)
			}
			appLogger.Success("✓ Domain file contains %d entries", count)
		}

		// Check nameservers are reachable
		appLogger.Info("Checking nameserver connectivity...")
		for _, ns := range config.Nameservers {
			conn, err := net.DialTimeout("udp", ns+":53", 2*time.Second)
			if err != nil {
				appLogger.Warn("✗ Nameserver %s is not reachable: %v", ns, err)
			} else {
				conn.Close()
				appLogger.Success("✓ Nameserver %s is reachable", ns)
			}
		}

		// Estimate memory usage
		if *domainsFile != "" {
			count, _ := countLines(*domainsFile)
			estimatedMem := (count * 100) / 1024 / 1024 // Rough estimate: 100 bytes per domain
			appLogger.Info("📊 Estimated memory usage: ~%d MB", estimatedMem)
		}

		appLogger.Success("✓ Dry-run validation completed successfully!")
		os.Exit(0)
	}

	shutdownChan := make(chan struct{})
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Println() // New line to clear any progress display
		appLogger.Warn("🛑 Received %v signal. Initiating graceful shutdown...", sig)
		appLogger.Info("⏳ Please wait while we clean up resources...")
		close(shutdownChan)

		// Give adequate time for cleanup
		timeout := 15 * time.Second

		<-time.After(timeout)
		appLogger.Fatal("⚠️  Shutdown timeout reached after %v. Forcing exit.", timeout)
		os.Exit(1)
	}()

	link, err := netlink.LinkByName(config.NIC)
	if err != nil {
		appLogger.Fatal("couldn't find interface %s: %v", config.NIC, err)
	}

	if config.SrcIP == "" {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil || len(addrs) == 0 {
			appLogger.Fatal("failed to get IPv4 address for interface %s: %v", config.NIC, err)
		}
		config.SrcIP = addrs[0].IP.String()
		appLogger.Info("Using source IP %s from interface %s", config.SrcIP, config.NIC)
	}

	bpfExited := make(chan struct{})
	go func() {
		defer close(bpfExited)
		BpfReceiver(config)
		appLogger.Info("BPF Receiver goroutine finished.")
	}()
	select {
	case <-startedBPF:
		appLogger.Success("BPF receiver started successfully.")
	case <-time.After(5 * time.Second):
		appLogger.Fatal("Error: Timed out waiting for BPF receiver to start.")
	}

	var totalDomainsInFile int // Declare here to be in scope for all branches

	if *domainsFile == "" && config.DomainName == "" {
		appLogger.Fatal("Error: Must provide a domain via -domain or a list via -domains")
	} else if *domainsFile != "" {
		appLogger.Info("Counting total domains in file for progress reporting...")
		var err error
		totalDomainsInFile, err = countLines(*domainsFile)
		if err != nil {
			appLogger.Fatal("Error counting lines in domains file: %v", err)
		}
		appLogger.Success("Found %d total domains.", totalDomainsInFile)
	} else {
		totalDomainsInFile = 1
	}

	if *nameserversFile != "" {
		// This is a temporary solution for the nameservers file.
		// A full streaming implementation for nameservers would be ideal in the future.
		loadedNameservers, err := readDomainsFromFile(*nameserversFile)
		if err != nil {
			appLogger.Fatal("Error reading nameservers file '%s': %v", *nameserversFile, err)
		}
		config.Nameservers = loadedNameservers
		appLogger.Success("Loaded %d nameservers from %s", len(config.Nameservers), *nameserversFile)
	} else if len(config.Nameservers) > 0 {
		appLogger.Info("Using default nameservers: %v", config.Nameservers)
	} else {
		appLogger.Fatal("Error: No nameservers loaded or defined in default config.")
	}

	opts := &xdp.SocketOptions{
		NumFrames:              4096,
		FrameSize:              2048,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 2048,
		RxRingNumDescs:         64,
		TxRingNumDescs:         2048,
	}
	appLogger.Info("Initializing XDP socket on interface %s queue %d", config.NIC, config.QueueID)
	xsk, err := xdp.NewSocket(link.Attrs().Index, config.QueueID, opts)
	if err != nil {
		appLogger.Fatal("Error creating XDP socket on %s queue %d: %v. Ensure driver support and sufficient privileges.", config.NIC, config.QueueID, err)
	}
	defer func() {
		appLogger.Info("Closing XDP socket...")
		xsk.Close()
		appLogger.Success("XDP socket closed.")
	}()

	// Create error grouper for smart error categorization
	errorGrouper := NewErrorGrouper()

	appLogger.Info("Starting packet transmission process...")
	if *domainsFile != "" {
		err = transmitPackets(xsk, *domainsFile, config, shutdownChan, totalDomainsInFile, errorGrouper)
	} else {
		// To handle the single-domain case without major refactoring of transmitPackets,
		// we can wrap it in a temporary structure.
		// A more elegant solution might be to have transmitPackets accept a channel directly.
		tempDomainFile := "temp-single-domain.txt"
		err = os.WriteFile(tempDomainFile, []byte(config.DomainName), 0644)
		if err == nil {
			err = transmitPackets(xsk, tempDomainFile, config, shutdownChan, totalDomainsInFile, errorGrouper)
		}
		os.Remove(tempDomainFile)
	}
	if err != nil {
		appLogger.Error("Transmission process encountered an error: %v", err)
	} else {
		appLogger.Success("Transmission process completed.")
	}

	appLogger.Info("Signaling BPF receiver to stop...")
	close(stopper)
	appLogger.Info("Waiting for BPF receiver to exit gracefully...")
	select {
	case <-bpfExited:
		appLogger.Success("BPF receiver exited.")
	case <-time.After(5 * time.Second):
		appLogger.Warn("Timed out waiting for BPF receiver to exit.")
	}

	// Display error summary if any errors occurred
	if errorSummary := errorGrouper.GetSummary(); errorSummary != "" {
		fmt.Print(errorSummary)
	}

	appLogger.Success("✨ PugDNS finished successfully!")
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

	appLogger.Info("--- Performance Analysis ---")
	for _, stat := range statsList {
		appLogger.Info("%-20s: %6.2f%% | Avg: %-15s | Calls: %d",
			stat.Name, stat.Percentage, stat.AvgTime, stat.Count)
	}
}

func bottleneckReporter(ctx context.Context, config *Config) {
	if !config.Verbose {
		return
	}
	appLogger.Info("Bottleneck reporter started.")
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			printPerformanceReport(config)
		}
	}
}

func checkAndRetryDomains(ctx context.Context, domainStates *haxmap.Map[string, *DomainStatus], packetQueue chan<- PacketInfo, packetTemplate []byte, config *Config, rng *rand.Rand, failedDomainsList *[]string, writeChan chan<- []byte, finalDrain bool) (pendingCount int) {
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
				atomic.AddUint64(&respondedDomainsCount, 1)

				// Track first-attempt success rate
				if status.AttemptsMade == 1 {
					atomic.AddUint64(&firstAttemptSuccesses, 1)
				} else if status.AttemptsMade > 1 {
					// This domain required retries
					atomic.AddUint64(&domainsRequiringRetries, 1)
				}
			}
		}

		if status.Responded {
			domainsToRemove = append(domainsToRemove, fqdn)
			atomic.AddUint64(&totalDomainsProcessed, 1)
		} else if status.AttemptsMade >= maxRetries {
			domainsToRemove = append(domainsToRemove, fqdn)
			*failedDomainsList = append(*failedDomainsList, fqdn)
			atomic.AddUint64(&totalDomainsProcessed, 1)
			// Count as requiring retries since it went through multiple attempts
			if status.AttemptsMade > 1 {
				atomic.AddUint64(&domainsRequiringRetries, 1)
			}
		} else if !status.LastAttempt.IsZero() && now.Sub(status.LastAttempt) > config.RetryTimeout {
			domainsToRetry[fqdn] = status.AttemptsMade
		} else {
			currentPending++
		}

		status.mu.Unlock()
		return true // Continue iteration
	})

	for _, fqdn := range domainsToRemove {
		// For succeeded domains, send the payload to be written before deleting.
		if payload, ok := cache.Get(fqdn); ok {
			if finalDrain {
				select {
				case writeChan <- payload:
				case <-ctx.Done():
					// If context is cancelled during final drain, just stop sending.
					return
				}
			} else {
				writeChan <- payload
			}
		}
		domainStates.Del(fqdn)
		// Do not delete from cache, so we can use it for deduplication against the input file.
		// cache.Del(fqdn)
	}

	if finalDrain {
		// During the final drain, we don't want to retry domains, just collect pending ones.
		domainStates.ForEach(func(fqdn string, status *DomainStatus) bool {
			*failedDomainsList = append(*failedDomainsList, fqdn)
			return true
		})
		return 0
	}

	queuedCount := 0
	failedToPrepareCount := 0

	if len(domainsToRetry) > 0 {
		for fqdn, currentAttempt := range domainsToRetry {
			// Check again right before sending to avoid race condition where
			// a response arrived after the domain was added to the retry list.
			if _, found := cache.Get(fqdn); found {
				continue
			}

			currentNameserver := config.Nameservers[rng.Intn(len(config.Nameservers))]
			dstIP := net.ParseIP(currentNameserver)
			if dstIP == nil {
				appLogger.Warn("Error preparing retry packet for %s: Invalid nameserver IP %s. Marking failed.", fqdn, currentNameserver)
				failedToPrepareCount++
				domainStates.Del(fqdn)
				*failedDomainsList = append(*failedDomainsList, fqdn)
				atomic.AddUint64(&totalDomainsProcessed, 1)
				continue
			}
			packetBytes, err := prepareSinglePacket(packetTemplate, fqdn, dstIP, rng)
			if err != nil {
				appLogger.Warn("Error preparing retry packet for %s (attempt %d): %v. Marking failed.", fqdn, currentAttempt+1, err)
				failedToPrepareCount++
				domainStates.Del(fqdn)
				*failedDomainsList = append(*failedDomainsList, fqdn)
				atomic.AddUint64(&totalDomainsProcessed, 1)
				continue
			}

			pktInfo := PacketInfo{Domain: fqdn, PacketBytes: packetBytes, Attempt: currentAttempt + 1}
			packetQueue <- pktInfo
			queuedCount++

			// Track retry attempts
			atomic.AddUint64(&totalRetryAttempts, 1)

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
