package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe" // Needed for size calculation

	"github.com/alphadose/haxmap"
	"github.com/cilium/ebpf" // Need this for map iteration
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
)

// --- CACHE, STOPPER, STARTEDBPF remain the same ---
var (
	cache      = haxmap.New[string, *dns.Msg]()
	stopper    = make(chan os.Signal, 1)
	startedBPF = make(chan bool, 1)
	// Separate counters for different drop reasons
	userspaceDropCount uint64 // User-space drops (packetChan full)
	bpfDropCount       uint64 // Kernel BPF drops (ringbuf full)
	dropMutex          sync.RWMutex
)

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

	numWorkers := config.NumWorkers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	// Channel still holds raw bytes from ring buffer samples
	packetChan := make(chan []byte, numWorkers*1024*1024*8) // Keep reasonable buffer

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	// Start worker goroutines
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			var meta dnsEventMeta // Reusable metadata struct per worker

			for rawSample := range packetChan { // Receive raw byte slice

				// 1. Validate minimum size for metadata
				if len(rawSample) < metaSize {
					// if config.Verbose { // Avoid log spam
					// 	log.Printf("Worker %d: Received short sample (%d bytes) < metaSize (%d)", workerID, len(rawSample), metaSize)
					// }
					continue
				}

				// 2. Read metadata from the beginning of the sample
				// Use a bytes.Reader for convenient reading
				reader := bytes.NewReader(rawSample)
				if err := binary.Read(reader, binary.LittleEndian, &meta); err != nil {
					log.Printf("Worker %d: Failed reading metadata: %s", workerID, err)
					continue
				}

				// 3. Validate declared payload size
				if meta.PayloadSize == 0 {
					// if config.Verbose {
					// 	log.Printf("Worker %d: Received sample with zero payload size from DestPort %d.", workerID, meta.DestPort)
					// }
					continue
				}
				// Check if declared size fits within the *remaining* buffer
				// reader.Len() now gives the number of bytes *after* reading meta
				if int(meta.PayloadSize) > reader.Len() {
					log.Printf("Worker %d: Declared payload size (%d) > remaining sample size (%d) for DestPort %d.", workerID, meta.PayloadSize, reader.Len(), meta.DestPort)
					continue
				}

				// 4. Extract the payload slice (no copy needed)
				// It starts right after the metadata in the original slice
				dnsPayload := rawSample[metaSize : metaSize+int(meta.PayloadSize)]

				// 5. Unpack the DNS message
				msg := new(dns.Msg)
				err := msg.Unpack(dnsPayload)
				if err != nil {
					// DNS unpacking errors can be common (malformed responses, etc.)
					// Log less verbosely unless debugging
					// if config.Verbose {
					// 	log.Printf("Worker %d: Failed unpacking DNS payload (%d bytes) for DestPort %d: %s", workerID, len(dnsPayload), meta.DestPort, err)
					// }
					continue
				}

				// 6. Check for Question section (needed for cache key)
				if len(msg.Question) == 0 {
					// if config.Verbose {
					// 	log.Printf("Worker %d: Received DNS msg with no questions for DestPort %d.", workerID, meta.DestPort)
					// }
					continue
				}

				if msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeRefused {
					continue
				}

				// 7. Store in cache using FQDN from question
				fqdn := msg.Question[0].Name // miekg/dns ensures this is FQDN
				cache.Set(fqdn, msg)
				atomic.AddUint64(&receivedPackets, 1) // Increment total SUCCESSFUL processing count

				if config.Verbose {
					log.Printf("Worker %d: Processed response for %s (ID: %d, DestPort: %d)", workerID, fqdn, msg.Id, meta.DestPort)
				}
			}
		}(i) // Pass worker ID
	}

	// Main event loop: Read from ring buffer and dispatch to workers
	for {
		record, err := rd.Read() // Blocking read
		if err != nil {
			// Check if the error is because the reader was closed
			if errors.Is(err, ringbuf.ErrClosed) {
				break // Exit loop cleanly
			}
			// Log other unexpected errors
			log.Printf("Error reading from ring buffer: %s", err)
			continue
		}

		// Send the raw sample bytes to the worker channel (non-blocking)
		select {
		case packetChan <- record.RawSample:
			// Sent successfully to a worker
		default:
			// If the channel is full, workers are falling behind
			atomic.AddUint64(&userspaceDropCount, 1)
			// Log this periodically to avoid spamming logs
			if userspaceDropCount%1000 == 1 { // Log every 1000 user-space drops

				log.Printf("Warning: BPF worker channel full. Dropping packet. (User-space drops: %d)", userspaceDropCount)
			}
		}
	}

	// Cleanup after the loop exits (due to rd.Close() via stopper)
	close(packetChan) // Signal workers no more data is coming
	wg.Wait()         // Wait for all workers to process remaining data and exit
}
