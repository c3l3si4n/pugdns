package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/alphadose/haxmap"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
)

var (
	cache      = haxmap.New[string, *dns.Msg]()
	stopper    = make(chan os.Signal, 1)
	startedBPF = make(chan bool, 1)
)

func BpfReceiver(config *Config) {
	// Subscribe to signals for terminating the program.
	log.Println("Starting BpfReceiver")
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs pugdnsObjects
	if err := loadPugdnsObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := config.NIC // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.DumpDnsPackets,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()
	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")
	startedBPF <- true

	// has to stop when signal is received
	for {
		select {
		case <-stopper:
			log.Println("Received signal, exiting..")
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("reading from reader: %s", err)
				continue
			}

			udpEvent := struct {
				SrcPort uint16
				DstPort uint16
				Length  uint16
				Data    [1500]byte
			}{}
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &udpEvent)
			if err != nil {
				log.Printf("reading from buffer: %s", err)
				continue
			}

			udpData := udpEvent.Data[:udpEvent.Length]
			// parse dns packet
			msg := new(dns.Msg)
			err = msg.Unpack(udpData)
			if err != nil {
				log.Printf("unpacking dns packet: %s", err)
				continue
			}

			cache.Set(msg.Question[0].Name, msg)

		}

	}

}
