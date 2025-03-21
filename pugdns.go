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
	"time"

	"github.com/alphadose/haxmap"
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

// StatsModel represents the UI model for statistics
type StatsModel struct {
	totalPackets     uint64
	packetsPerSec    uint64
	avgPacketsPerSec float64
	receivedPackets  uint64
	progressBar      progress.Model
	startTime        time.Time
	duration         float64
	width            int
	height           int
	quitting         bool
}

// Initialize sets up the initial model
func (m StatsModel) Init() tea.Cmd {
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
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progressBar.Width = msg.Width - 20
		return m, nil

	case statsUpdateMsg:
		m.totalPackets = msg.totalPackets
		m.packetsPerSec = msg.packetsPerSec
		m.avgPacketsPerSec = msg.avgPacketsPerSec
		m.duration = msg.duration
		if m.totalPackets > 0 {
			progress := float64(m.totalPackets) / neededNumberOfPackets
			m.progressBar.SetPercent(progress)
		}
		return m, nil

	case tickMsg:
		return m, tickCmd()
	}

	return m, nil
}

// View renders the current state of the model
func (m StatsModel) View() string {
	if m.quitting {
		return "Transmission complete!\n"
	}

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		Render("DNS QUERY STATISTICS")

	stats := fmt.Sprintf("\nTotal Packets: %d\nReceived Packets: %d\nCurrent Rate: %d pps\nAverage Rate: %.2f pps\nRuntime: %.1f seconds",
		m.totalPackets, m.receivedPackets, m.packetsPerSec, m.avgPacketsPerSec, m.duration)

	progress := "\nProgress:\n" + m.progressBar.ViewAs(float64(m.totalPackets)/neededNumberOfPackets)

	help := "\nPress q to quit"

	return lipgloss.JoinVertical(lipgloss.Left, title, stats, progress, help)
}

type statsUpdateMsg struct {
	totalPackets     uint64
	packetsPerSec    uint64
	avgPacketsPerSec float64
	duration         float64
	receivedPackets  uint64
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

// preparePackets generates DNS query packets for each domain
func preparePackets(
	domains []string,
	config *Config,
	srcMAC, dstMAC net.HardwareAddr,
	srcIP net.IP,
) (*haxmap.Map[int, []byte], error) {
	packetMap := haxmap.New[int, []byte]()
	rng := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))

	fmt.Printf("Preparing packets for %d domains to %d nameservers...\n",
		len(domains), len(config.Nameservers))

	for i, domain := range domains {
		// Select a random nameserver for each domain
		currentNameserver := config.Nameservers[rng.Intn(len(config.Nameservers))]

		// Create Ethernet layer
		eth := &layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		}

		// Create IP layer
		ip := &layers.IPv4{
			Version:  4,
			IHL:      5,
			TTL:      64,
			Id:       0,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    srcIP,
			DstIP:    net.ParseIP(currentNameserver),
		}

		// Create UDP layer
		udp := &layers.UDP{
			SrcPort: 1234,
			DstPort: 53,
		}
		udp.SetNetworkLayerForChecksum(ip)

		// Create DNS query
		query := new(dns.Msg)
		query.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		dnsPayload, err := query.Pack()
		if err != nil {
			// skip this domain
			continue
		}

		// Serialize all layers
		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(dnsPayload))
		if err != nil {
			// skip this domain
			continue
		}

		packetMap.Set(i, buf.Bytes())
	}

	go HandleResponses(domains, config.OutputFile)

	return packetMap, nil
}

var receivedPackets uint64

// statsCollector handles collecting and displaying transmission statistics
func statsCollector(xsk *xdp.Socket, stopStats <-chan struct{}, programDone chan<- struct{}, config *Config) {
	var prev, cur xdp.Stats
	var err error

	startTime := time.Now()
	var totalPacketsSent uint64

	var p *tea.Program

	// Only initialize Bubble Tea if text output is not requested
	if !config.TextOutput {
		// Initialize Bubble Tea
		p = tea.NewProgram(
			StatsModel{
				progressBar: progress.New(progress.WithDefaultGradient()),
				startTime:   time.Now(),
			},
			tea.WithAltScreen(),
		)

		// Launch UI in a separate goroutine
		go func() {
			if _, err := p.Run(); err != nil {
				log.Printf("UI error: %v", err)
			}
			programDone <- struct{}{}
		}()
	} else {
		// For text output, just print the header
		fmt.Println("\nDNS QUERY STATISTICS")
		fmt.Println("--------------------")
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cur, err = xsk.Stats()
			if err != nil {
				log.Printf("Failed to get stats: %v", err)
				continue
			}

			packetsSent := cur.Completed - prev.Completed
			totalPacketsSent += packetsSent

			duration := time.Since(startTime).Seconds()
			avgPPS := float64(totalPacketsSent) / duration

			if !config.TextOutput {
				// Update the UI
				p.Send(statsUpdateMsg{
					totalPackets:     totalPacketsSent,
					packetsPerSec:    packetsSent,
					avgPacketsPerSec: avgPPS,
					duration:         duration,
					receivedPackets:  receivedPackets,
				})
			} else {
				// Print text statistics
				progress := float64(totalPacketsSent) / neededNumberOfPackets * 100
				fmt.Printf("\rTotal: %d | Rate: %d pps | Avg: %.2f pps | Time: %.1fs | Progress: %.1f%%",
					totalPacketsSent, packetsSent, avgPPS, duration, progress)
			}

			prev = cur
		case <-stopStats:
			// Final stats
			cur, _ = xsk.Stats()
			totalPacketsSent = cur.Completed
			duration := time.Since(startTime).Seconds()

			if !config.TextOutput {
				// Update the UI one last time
				p.Send(statsUpdateMsg{
					totalPackets:     totalPacketsSent,
					packetsPerSec:    0,
					avgPacketsPerSec: float64(totalPacketsSent) / duration,
					duration:         duration,
					receivedPackets:  receivedPackets,
				})

				// Give UI time to update
				time.Sleep(100 * time.Millisecond)
				p.Quit()
			} else {
				// Print final text statistics
				fmt.Printf("\n\nTransmission complete!")
				fmt.Printf("\nTotal Packets: %d", totalPacketsSent)
				fmt.Printf("\nReceived Packets: %d", receivedPackets)
				fmt.Printf("\nAverage Rate: %.2f pps", float64(totalPacketsSent)/duration)
				fmt.Printf("\nTotal Runtime: %.1f seconds\n\n", duration)
				programDone <- struct{}{}
			}
			return
		}
	}
}

// transmitPackets handles the XDP transmission of prepared packets
func transmitPackets(xsk *xdp.Socket, packetMap *haxmap.Map[int, []byte], config *Config) error {
	// Get packet keys for iteration
	packetKeys := make([]int, 0, packetMap.Len())
	packetMap.ForEach(func(key int, _ []byte) bool {
		packetKeys = append(packetKeys, key)
		return true
	})

	fmt.Printf("Starting transmission of %d unique DNS query packets\n", len(packetKeys))

	// Start statistics collection
	stopStats := make(chan struct{})
	programDone := make(chan struct{})
	go statsCollector(xsk, stopStats, programDone, config)

	// Track packet transmission status
	packetCount := len(packetKeys)
	packetsSent := make([]bool, packetCount)
	packetsRemaining := packetCount

	// Get available descriptors for transmission
	allDescs := xsk.GetDescs(packetCount, false)
	if len(allDescs) == 0 {
		return fmt.Errorf("no descriptors available for transmission")
	}

	fmt.Printf("Got %d descriptors for transmitting packets\n", len(allDescs))

	// Fill initial descriptors with packets
	currentPacketIndex := 0
	for i := range allDescs {
		if packetsRemaining == 0 {
			allDescs = allDescs[:i]
			break
		}

		packetKey := packetKeys[currentPacketIndex]
		packet, _ := packetMap.Get(packetKey)
		frameLen := copy(xsk.GetFrame(allDescs[i]), packet)
		allDescs[i].Len = uint32(frameLen)

		if !packetsSent[currentPacketIndex] {
			packetsSent[currentPacketIndex] = true
			packetsRemaining--
		}

		currentPacketIndex = (currentPacketIndex + 1) % packetCount
	}

	// Initial transmission
	if len(allDescs) > 0 {
		xsk.Transmit(allDescs)
	}
	neededNumberOfPackets = float64(packetsRemaining)
	// Main transmission loop
	for packetsRemaining > 0 {
		// Poll for completions
		_, _, err := xsk.Poll(20)
		if err != nil && err != unix.ETIMEDOUT {
			return fmt.Errorf("poll error: %w", err)
		}

		// Process completed transmissions
		numCompleted := xsk.NumCompleted()
		if numCompleted > 0 {
			xsk.Complete(numCompleted)
		}

		// Get available descriptors for next batch
		descs := xsk.GetDescs(xsk.NumFreeTxSlots(), false)
		if len(descs) == 0 {
			continue
		}

		// Fill descriptors with unsent packets
		descsToTransmit := 0
		for i := range descs {
			// Find next unsent packet
			for currentPacketIndex < packetCount && packetsSent[currentPacketIndex] {
				currentPacketIndex = (currentPacketIndex + 1) % packetCount
				if currentPacketIndex == 0 && packetsRemaining == 0 {
					break
				}
			}

			if packetsRemaining == 0 {
				break
			}

			packetKey := packetKeys[currentPacketIndex]
			packet, _ := packetMap.Get(packetKey)
			frameLen := copy(xsk.GetFrame(descs[i]), packet)
			descs[i].Len = uint32(frameLen)
			descsToTransmit++

			if !packetsSent[currentPacketIndex] {
				packetsSent[currentPacketIndex] = true
				packetsRemaining--
			}

			currentPacketIndex = (currentPacketIndex + 1) % packetCount
		}

		// Submit packets for transmission
		if descsToTransmit > 0 {
			if config.Verbose {
				log.Printf("Transmitting %d packets (%d remaining)", descsToTransmit, packetsRemaining)
			}
			xsk.Transmit(descs[:descsToTransmit])
		}
	}

	// Ensure all packets are sent
	finalizeTransmission(xsk)

	// Stop statistics collection
	close(stopStats)

	// Wait for UI to finish
	<-programDone

	return nil
}

// finalizeTransmission ensures all packets are properly transmitted
func finalizeTransmission(xsk *xdp.Socket) {
	// Wait for remaining packets to be transmitted
	time.Sleep(100 * time.Millisecond)

	// Process any remaining completions
	for xsk.NumTransmitted() > 0 {
		_, _, err := xsk.Poll(100)
		if err != nil && err != unix.ETIMEDOUT {
			log.Printf("Final poll error: %v", err)
			break
		}

		if xsk.NumCompleted() > 0 {
			completed := xsk.NumCompleted()
			xsk.Complete(completed)
			if completed > 0 {
				log.Printf("Finalized %d completed packets", completed)
			}
		}
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

func HandleResponses(queriedDomains []string, outputFile string) {
	// Create a map of domains to their responses. Once all domains are found in the haxmap, save the results to a file once finished.
	domainAlreadyFound := make(map[string]bool)
	resultsArray := []*dns.Msg{}

	for {
		foundAllDomains := true
		for _, domain := range queriedDomains {
			domainFqdn := dns.Fqdn(domain)
			if domainAlreadyFound[domainFqdn] {
				continue
			}
			foundAllDomains = false
			foundDomain, ok := cache.Get(domainFqdn)
			if ok {
				domainAlreadyFound[domainFqdn] = true
				resultsArray = append(resultsArray, foundDomain)
				receivedPackets++
				AppendToFile(foundDomain, outputFile)

			}
		}
		if foundAllDomains {
			break
		}
	}

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

	flag.StringVar(&config.OutputFile, "output", config.OutputFile, "File to save results to")
	flag.Parse()

	// Validate required parameters
	if config.NIC == "" {
		log.Fatal("Error: interface (-interface) is required")
	}

	startTime := time.Now()

	// Initialize the interface
	link, err := netlink.LinkByName(config.NIC)
	if err != nil {
		log.Fatalf("Error: couldn't find interface %s: %v", config.NIC, err)
	}

	// Start BPF receiver
	go BpfReceiver(config)
	<-startedBPF
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

	// Resolve MAC addresses
	srcMAC, dstMAC, err := ResolveMACAddresses(config, link)
	if err != nil {
		log.Fatalf("Error resolving MAC addresses: %v", err)
	}

	fmt.Printf("Sending DNS queries from %v (%v) to nameservers via MAC %v\n",
		config.SrcIP, srcMAC, dstMAC)

	// Prepare DNS query packets
	srcIP := net.ParseIP(config.SrcIP)
	packetMap, err := preparePackets(domains, config, srcMAC, dstMAC, srcIP)
	if err != nil {
		log.Printf("Error preparing packets: %v", err)
	}

	// Initialize XDP socket
	xsk, err := xdp.NewSocket(link.Attrs().Index, config.QueueID, nil)
	if err != nil {
		log.Fatalf("Error creating XDP socket: %v", err)
	}

	// Transmit packets
	err = transmitPackets(xsk, packetMap, config)
	if err != nil {
		log.Fatalf("Error during transmission: %v", err)
	}
	// Print final summary
	fmt.Printf("\nTotal execution time: %.2f seconds\n", time.Since(startTime).Seconds())
	fmt.Printf("Average query rate: %.2f qps\n", float64(len(domains))/(time.Since(startTime).Seconds()))

	// Print final summary
	log.Println("Transmission complete. Sleeping for 2 seconds for bpf to finish receiving packets...")
	log.Println("Results saved to file: ", config.OutputFile)
	time.Sleep(5 * time.Second)

}
