//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>

/* Structure to hold the UDP payload data */
struct udp_event {
    __u16 source;
    __u16 dest;
    __u16 payload_size;
    __u8 payload[1500]; // Max UDP payload size
};

/* Ring buffer for sending events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
    __type(value, struct udp_event);
    // unfragmented
} events SEC(".maps");

char __license[] SEC("license") = "GPL";

SEC("xdp")
int dump_dns_packets(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Verify Ethernet header fits
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    // Check Ethernet protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // Verify IP header fits
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;

    // Check if it's UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Verify UDP header fits
    struct udphdr *udp = (void*)(ip + 1);
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;

    // Filter for DNS traffic (port 53)
    unsigned short src_port = 53;
    if (bpf_ntohs(udp->source) != src_port )
        return XDP_PASS;

    unsigned short dst_port = 1234;
    if (bpf_ntohs(udp->dest) != dst_port)
        return XDP_PASS;

    // Calculate UDP data length and verify
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len <= sizeof(*udp))
        return XDP_PASS;
    
    __u16 payload_size = udp_len - sizeof(*udp);
    
    // Payload starts right after UDP header
    void *payload_start = (void*)(udp + 1);
    
    // Boundary check for total payload
    if (payload_start + payload_size > data_end) {
        // Adjust payload size to what we can safely access
        payload_size = (void*)data_end - payload_start;
    }
    
    // Only process non-empty payloads
    if (payload_size <= 0)
        return XDP_PASS;
    
    // Reserve space in the ring buffer
    struct udp_event *event = bpf_ringbuf_reserve(&events, sizeof(struct udp_event), 0);
    if (!event)
        return XDP_PASS;
    
    // Populate the event
    event->source = bpf_ntohs(udp->source);
    event->dest = bpf_ntohs(udp->dest);
    event->payload_size = payload_size;
    
    // Copy payload data with strict bounds checking
    // We need this approach to satisfy the verifier
    __u32 bytes_copied = 0;
    __u8 *payload_ptr = payload_start;
    
    // This loop is carefully structured to satisfy the eBPF verifier
    #pragma unroll
    for (int i = 0; i < 1500 && bytes_copied < payload_size; i++) {
        if (payload_ptr + bytes_copied >= (void*)data_end)
            break;
            
        event->payload[bytes_copied] = *(__u8*)(payload_ptr + bytes_copied);
        bytes_copied++;
    }

    bpf_printk("Copied %d bytes\n", bytes_copied);
    
    // If we couldn't copy anything, discard the event
    if (bytes_copied == 0) {
        bpf_ringbuf_discard(event, 0);
        return XDP_PASS;
    }

    
    // Update the actual size we managed to copy
    event->payload_size = bytes_copied;
    
    // Submit the event to userspace
    bpf_ringbuf_submit(event, 0);
    
    return XDP_PASS;
}