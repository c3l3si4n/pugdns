package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"github.com/jackpal/gateway"
	"github.com/vishvananda/netlink"
)

// ResolveMAC resolves the MAC address for a given IP using the ARP table and gateway if needed
func ResolveMAC(ip string, link netlink.Link) (net.HardwareAddr, error) {
	// If IP is localhost, return the link's MAC address
	if ip == "127.0.0.1" {
		return link.Attrs().HardwareAddr, nil
	}

	// First try to find the MAC directly in the ARP table
	neighbors, err := netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to get ARP table: %v", err)
	}

	targetIP := net.ParseIP(ip)
	for _, neigh := range neighbors {
		if neigh.IP.Equal(targetIP) && len(neigh.HardwareAddr) != 0 {
			return neigh.HardwareAddr, nil
		}
	}

	// If not found directly, use gateway
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to discover gateway: %v", err)
	}

	// Look for the gateway MAC in the ARP table
	for _, neigh := range neighbors {
		if neigh.IP.Equal(gatewayIP) && len(neigh.HardwareAddr) != 0 {
			return neigh.HardwareAddr, nil
		}
	}

	// If gateway MAC not in ARP table, try to resolve it
	neighReq := &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		IP:        gatewayIP,
		State:     netlink.NUD_NONE,
		Flags:     netlink.NTF_USE,
	}

	if err := netlink.NeighSet(neighReq); err != nil {
		return nil, fmt.Errorf("failed to trigger ARP resolution for gateway %s: %v", gatewayIP, err)
	}

	// Wait a moment for ARP resolution
	time.Sleep(50 * time.Millisecond)

	// Check ARP table again
	neighbors, err = netlink.NeighList(link.Attrs().Index, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to get updated ARP table: %v", err)
	}

	for _, neigh := range neighbors {
		if neigh.IP.Equal(gatewayIP) && len(neigh.HardwareAddr) != 0 {
			return neigh.HardwareAddr, nil
		}
	}

	return nil, fmt.Errorf("could not resolve MAC address for gateway %s", gatewayIP)
}

// ResolveMACAddresses handles resolving both source and destination MAC addresses
func ResolveMACAddresses(config *Config, link netlink.Link) (srcMAC, dstMAC net.HardwareAddr, err error) {
	// Auto-resolve source MAC from interface if not provided
	if config.SrcMAC == "" {
		srcMAC = link.Attrs().HardwareAddr
	} else {
		decoded, err := hex.DecodeString(config.SrcMAC)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid source MAC address format: %v", err)
		}
		srcMAC = net.HardwareAddr(decoded)
	}

	// Auto-resolve destination MAC via ARP if not provided
	if config.DstMAC == "" {
		// Try to resolve the first nameserver
		resolvedMAC, err := ResolveMAC(config.Nameservers[0], link)
		if err != nil {
			fmt.Printf("Warning: %v\n", err)
			fmt.Println("Try pinging the destination or gateway first, or add a static ARP entry")
			fmt.Println("Falling back to broadcast MAC address")
			broadcast, _ := hex.DecodeString("ffffffffffff")
			dstMAC = net.HardwareAddr(broadcast)
		} else {
			dstMAC = resolvedMAC
		}
	} else {
		decoded, err := hex.DecodeString(config.DstMAC)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid destination MAC address format: %v", err)
		}
		dstMAC = net.HardwareAddr(decoded)
	}

	return srcMAC, dstMAC, nil
}
