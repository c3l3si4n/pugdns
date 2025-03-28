//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stddef.h>

#define MAX_DNS_PAYLOAD 4096

/* Metadata structure */
struct dns_event_meta {
    __u16 src_port;
    __u16 dest_port;
    __u16 payload_size;
};

/* Ring buffer map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 27); // 128MB
} events SEC(".maps");

/* Drops map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drops SEC(".maps");

char __license[] SEC("license") = "GPL";

// Define reserve_size globally as a const for clarity
const __u64 reserve_size = sizeof(struct dns_event_meta) + MAX_DNS_PAYLOAD;

SEC("xdp")
int dump_dns_packets(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    void *payload_start;
    __u16 payload_size; // Actual payload size for this packet
    __u16 dest_port_h;
    __u32 zero = 0;

    // 1. Ethernet Header Check
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. Check for IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 3. IP Header Check
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // 4. Check for UDP Protocol
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // 5. UDP Header Check (using ip->ihl)
    udp = (void*)((__u8*)ip + (ip->ihl * 4));
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // 6. Filter DNS Response Source Port (Port 53)
    if (udp->source != bpf_htons(53))
        return XDP_PASS;

    // 7. Filter Destination Port (Ephemeral Port Range)
    dest_port_h = bpf_ntohs(udp->dest);
    if (dest_port_h < 1024)
        return XDP_PASS;

    // 8. Calculate Actual UDP Payload Size for this packet
    payload_size = bpf_ntohs(udp->len) - sizeof(*udp);
    // Basic validation: Check if calculated size is non-positive or wraps around
    if ((short)payload_size <= 0) { // Cast to short to catch potential wrap-around for small udp->len
        return XDP_PASS;
    }

    // 9. Payload Boundary Check (Source Packet Data)
    payload_start = (void *)(udp + 1);
    // Check if payload_start + payload_size (from header) exceeds packet bounds
    if (payload_start + payload_size > data_end) {
         // Malformed/truncated packet according to UDP length header
         return XDP_PASS;
    }

    // ***** VERIFIER FIX: Explicitly check payload_size against MAX *before* use *****
    // Ensure the payload size we intend to copy doesn't exceed our limit.
    // The verifier can easily track this check.
    if (payload_size > MAX_DNS_PAYLOAD) {
        // Payload is larger than we want to handle. We could truncate,
        // but PASSing (dropping for our purpose) is simpler/safer.
        // bpf_printk("BPF: Payload size %u exceeds MAX %u. Dropping.\n", payload_size, MAX_DNS_PAYLOAD);
        return XDP_PASS;
    }
    // ***** At this point, the verifier KNOWS payload_size <= MAX_DNS_PAYLOAD *****


    // 11. Reserve MAX size in Ring Buffer
    struct dns_event_meta *meta = bpf_ringbuf_reserve(&events, reserve_size, 0);
    if (!meta) {
        // Ring buffer full, increment drop count
        __u64 *drop_count = bpf_map_lookup_elem(&drops, &zero);
        if (drop_count) {
             *drop_count += 1;
        }
        return XDP_PASS;
    }

    // 12. Populate Metadata (use the validated payload_size)
    meta->src_port = 53;
    meta->dest_port = dest_port_h;
    meta->payload_size = payload_size; // Store the validated size

    // 13. Copy ACTUAL Payload Data
    // Destination: (void*)meta + sizeof(*meta)
    // Source: payload_start
    // Size: payload_size (Now guaranteed <= MAX_DNS_PAYLOAD)
    int ret = bpf_probe_read_kernel((void*)meta + sizeof(*meta), payload_size, payload_start);
    if (ret < 0) {
        bpf_ringbuf_discard(meta, 0);
        // bpf_printk("BPF: probe_read_kernel failed: %d\n", ret);
        return XDP_PASS;
    }

    // 14. Submit
    bpf_ringbuf_submit(meta, 0);

    return XDP_PASS;
}