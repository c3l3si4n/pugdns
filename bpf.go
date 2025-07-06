package main

import (
	"encoding/binary"
	"errors"
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
	"unsafe" // Needed for size calculation

	"github.com/cilium/ebpf" // Need this for map iteration
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// --- CACHE, STOPPER, STARTEDBPF remain the same ---
var (
	// The cache is sharded to reduce lock contention from concurrent workers.
	// It is initialized in the main() function in pugdns.go.
	cache *ShardedHaxMap

	stopper    = make(chan os.Signal, 1)
	startedBPF = make(chan bool, 1)
	// Separate counters for different drop reasons
	userspaceDropCount uint64 // User-space drops (packetChan full)
	bpfDropCount       uint64 // Kernel BPF drops (ringbuf full)
	dropMutex          sync.RWMutex
)

// cacheWriteRequest is used to send data to the dedicated cache writer goroutine.
type cacheWriteRequest struct {
	fqdn    string
	payload []byte
}

// --- Definition matching the C struct ---
//
//	struct dns_event_meta {
//	    __u16 src_port;
//	    __u16 dest_port;
//	    __u16 payload_size;
//	};
type dnsEventMeta struct {
	SrcPort     uint16
	DestPort    uint16
	PayloadSize uint16
	// No padding needed usually for contiguous u16 fields
}

// Calculate size of the metadata struct dynamically
var metaSize = int(unsafe.Sizeof(dnsEventMeta{}))

// getFqdnFromDnsQuery manually parses the question section of a raw DNS payload
// to extract the FQDN. It's much faster than a full dns.Msg.Unpack().
func getFqdnFromDnsQuery(payload []byte) (string, bool) {
	// DNS header is 12 bytes. Question starts at byte 12.
	if len(payload) <= 12 {
		return "", false
	}

	var fqdn strings.Builder
	offset := 12

	for {
		if offset >= len(payload) {
			return "", false // Malformed, went past end of payload
		}

		labelLen := int(payload[offset])
		if labelLen == 0 {
			break // End of domain name
		}

		// Check for DNS compression pointers.
		if (labelLen & 0xC0) == 0xC0 {
			// Pointer detected. For simplicity in this hot path, we don't follow them.
			// The question in a response almost always matches the original question format
			// without compression. We just stop here.
			break
		}

		offset++ // move past length byte

		if offset+labelLen > len(payload) {
			return "", false // Malformed, label overflows payload
		}

		fqdn.Write(payload[offset : offset+labelLen])
		fqdn.WriteByte('.')

		offset += labelLen
	}

	if fqdn.Len() == 0 {
		return "", false // No name found
	}

	return fqdn.String(), true
}

func BpfReceiver(config *Config) {
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs pugdnsObjects
	if err := loadPugdnsObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := config.NIC
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DumpDnsPackets,
		Interface: iface.Index,
		// Consider XDPDriverMode if interface supports it for better performance
		// Flags:     link.XDPDriverMode,
		Flags: link.XDPGenericMode, // Fallback generic mode
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer l.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	// Defer rd.Close() handled by the stopper goroutine now

	// Goroutine to monitor BPF kernel drops
	go func() {
		ticker := time.NewTicker(2 * time.Second) // Check periodically
		defer ticker.Stop()

		// Assuming 'drops' map is defined as BPF_MAP_TYPE_PERCPU_ARRAY in C
		// and loaded correctly into objs.Drops (type *ebpf.Map)
		if objs.Drops == nil {
			log.Println("Warning: BPF drops map not loaded, cannot monitor kernel drops.")
			return
		}
		if objs.Drops.Type() != ebpf.PerCPUArray {
			log.Printf("Warning: BPF drops map is not PerCPUArray (type: %s), cannot monitor kernel drops correctly.", objs.Drops.Type())
			return
		}

		var perCPUValues []uint64 // Slice to hold values from all CPUs

		for {
			select {
			case <-stopper:
				return
			case <-ticker.C:
				var key uint32 = 0 // Key is always 0 for the first entry in the array
				var currentTotalDrops uint64

				// Lookup retrieves values for the key across all possible CPUs.
				// The map needs to be PerCPUArray or PerCPUHash.
				// We need to provide a slice large enough or nil.
				// Providing nil might be less efficient if map isn't empty often.
				// Let's try with a pre-sized slice based on NumCPU.
				if cap(perCPUValues) < runtime.NumCPU() {
					perCPUValues = make([]uint64, runtime.NumCPU())
				}

				// Lookup expects a pointer to a slice for PerCPU maps
				if err := objs.Drops.Lookup(&key, &perCPUValues); err == nil {
					for _, v := range perCPUValues {
						currentTotalDrops += v
					}

					dropMutex.Lock()
					// Only log if the count has increased
					if currentTotalDrops > bpfDropCount {
						log.Printf("Warning: %d new BPF ring buffer drops detected (total %d)", currentTotalDrops-bpfDropCount, currentTotalDrops)
						bpfDropCount = currentTotalDrops // Update the tracked total
					}
					dropMutex.Unlock()

				} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOENT) {
					// Log other errors (like permission issues, etc.)
					log.Printf("Error reading BPF drops map: %v", err)
					// Prevent spamming logs if map reading consistently fails
					time.Sleep(10 * time.Second)
				}
			}
		}
	}()

	// Goroutine to close the ring buffer reader when stopper is signaled
	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	startedBPF <- true // Signal main thread that BPF is ready

	// A single, tight loop for processing packets synchronously.
	// This avoids channel and goroutine overhead, which was the bottleneck.
	for {
		record, err := rd.Read() // Blocking read
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break // Exit loop cleanly
			}
			log.Printf("Error reading from ring buffer: %s", err)
			continue
		}

		// The record's memory is only valid until the next Read() call.
		// We process it immediately and make a right-sized copy for the cache.
		rawSample := record.RawSample

		if len(rawSample) < metaSize {
			continue
		}

		// Manually decode metadata
		metaPayloadSize := binary.LittleEndian.Uint16(rawSample[4:6])

		if metaPayloadSize == 0 {
			continue
		}
		if int(metaPayloadSize) > len(rawSample)-metaSize {
			continue
		}

		dnsPayload := rawSample[metaSize : metaSize+int(metaPayloadSize)]

		fqdn, ok := getFqdnFromDnsQuery(dnsPayload)
		if !ok {
			continue
		}

		// This is the single, essential copy to prevent the ring buffer's
		// memory from being held in our cache.
		payloadToCache := make([]byte, len(dnsPayload))
		copy(payloadToCache, dnsPayload)

		cache.Set(fqdn, payloadToCache)
		atomic.AddUint64(&receivedPackets, 1)

	}
}
