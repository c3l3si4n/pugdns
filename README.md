# pugDNS 🐾
![pugDNS](pug.png)

An experimental high-performance DNS query tool built with **AF_XDP** and **eBPF** for extremely fast and accurate bulk DNS lookups. pugDNS uses an eBPF filter to efficiently capture DNS responses directly in the kernel, complementing its high-speed query injection capabilities.

## Overview

pugDNS is designed for security researchers, network administrators, and penetration testers who need to perform DNS reconnaissance at scale. By leveraging AF_XDP sockets for packet transmission and eBPF for response capturing, pugDNS can send queries and process responses at rates significantly higher than traditional tools, making it ideal for domain discovery, enumeration, and validation tasks.

pugDNS will easily saturate your network link, so it's recommended to use this tool on a server with a high-speed internet connection and appropriate network configuration (e.g., ensuring the gateway MAC is correctly resolved or specified).

## Performance

pugDNS is designed to be as fast as possible. It uses AF_XDP sockets to directly inject DNS queries into the network driver (or kernel, depending on mode), bypassing much of the usual network stack. This allows it to send DNS queries and process responses with significantly better throughput and latency than traditional tools.

The following benchmarks were performed on an AX41 Hetzner server (AMD Ryzen 5 3600) with a 1Gbit/s port. Benchmarking pugDNS against other popular DNS tools, we observed the following results using a ~20k domain list:

*(Note: Benchmarks are indicative and can vary based on hardware, network conditions, and target nameservers. The original benchmarks were run on slightly different hardware but show the relative performance gains.)*

```bash
# Example benchmark results (replace with updated numbers if available)
Benchmark 1: cat wordlist.txt | dnsx -retry 1 -r a.txt
  Time (mean ± σ):     5.530 s ±  0.014 s    [User: 0.870 s, System: 1.002 s]
  Range (min … max):   5.514 s …  5.539 s    3 runs

Benchmark 2: cat wordlist.txt | zdns A --retries 1 --name-servers @a.txt >/dev/null
  Time (mean ± σ):     2.350 s ±  0.089 s    [User: 1.979 s, System: 0.659 s]
  Range (min … max):   2.283 s …  2.451 s    3 runs

Benchmark 3: massdns  -r a.txt -s 12000 -c 1  wordlist.txt  >/dev/null
  Time (mean ± σ):     616.6 ms ±   4.7 ms    [User: 25.5 ms, System: 107.8 ms]
  Range (min … max):   612.0 ms … 621.3 ms    3 runs

Benchmark 4: ./pugdns -interface enp6s0 -domains wordlist.txt -nameservers a.txt -retries 1
  Time (mean ± σ):     186.6 ms ±   4.3 ms    [User: 33.9 ms, System: 48.7 ms]
  Range (min … max):   181.9 ms … 190.5 ms    3 runs

Summary
  ./pugdns -interface enp6s0 -domains wordlist.txt -nameservers a.txt -retries 1 ran
    3.30 ± 0.08 times faster than massdns  -r a.txt -s 12000 -c 1  wordlist.txt  >/dev/null
   12.59 ± 0.56 times faster than cat wordlist.txt | zdns A --retries 1 --name-servers @a.txt >/dev/null
   29.64 ± 0.69 times faster than cat wordlist.txt | dnsx -retry 1 -r a.txt
```

Looking into the accuracy and number of responses that came back, we had the following numbers testing with a 19966 domain wordlist:

| Tool    | Accuracy | Number of Responses |
| :------ | :------- | :------------------ |
| pugdns  | 100%     | 19969               |
| massdns | 99.994%  | 19968               |
| zdns    | 100%     | 19969               |
| dnsx    | 99.984%  | 19966               |

## Features & Roadmap

-   [x] High-speed DNS query transmission via AF_XDP raw sockets
-   [x] Asynchronous architecture using dedicated goroutines for packet sending, response handling, and state management.
-   [x] Multi-threaded processing of DNS responses via eBPF and a configurable worker pool (goroutines).
-   [x] Support for multiple nameservers and large domain lists via input files
-   [x] Efficient DNS response capturing using eBPF
-   [x] Automatic query retries for unanswered domains
-   [x] Kernel and user-space drop monitoring for observability
-   [x] Configurable number of workers, retries, and poll timeouts
-   [x] Interactive UI (default) or simple text output for progress
-   [x] Results saved in JSON format
-   [ ] Support for different DNS record types (AAAA, MX, etc.)
-   [ ] IPv6 support
-   [ ] Dynamic rate limiting options

## Command-Line Flags

| Flag          | Type   | Default                     | Description                                                               | Required |
| :------------ | :----- | :-------------------------- | :------------------------------------------------------------------------ | :------- |
| `-interface`  | string | ""                          | Network interface name to use (e.g., `eth0`, `enp6s0`)                    | **Yes** |
| `-queue`      | int    | 0                           | Network interface queue ID to bind to                                     | No       |
| `-srcMAC`     | string | ""                          | Source MAC address (Default: auto-detected from interface)                | No       |
| `-dstMAC`     | string | ""                          | Destination MAC address (Gateway) (Default: auto-detected via ARP/NDP)    | No       |
| `-srcIP`      | string | ""                          | Source IP address (Default: auto-detected from interface)                 | No       |
| `-domain`     | string | "google.com"                | Single domain to query (used if `-domains` is not specified)              | No       |
| `-domains`    | string | ""                          | File containing domains to query (one per line)                           | No       |
| `-nameservers`| string | ""                          | File containing nameserver IPs (one per line)                             | **Yes** |
| `-output`     | string | "results.json"              | File to save results to (pretty JSON format)                              | No       |
| `-verbose`    | bool   | false                       | Enable verbose logging output                                             | No       |
| `-text`       | bool   | false                       | Use simple text output instead of the default interactive UI              | No       |
| `-poll`       | int    | 1                           | AF_XDP poll timeout in milliseconds (for TX completion)                   | No       |
| `-workers`    | int    | *# logical CPUs* | Number of workers for processing BPF responses                            | No       |
| `-retries`    | int    | 3                           | Number of retries for domains that don't receive a response               | No       |

**Example Usage:**

```bash
# Query domains from domains.txt using nameservers from resolvers.txt on interface eth0
sudo ./pugdns -interface eth0 -domains domains.txt -nameservers resolvers.txt -output my_results.json
```
*(Note: Running with `sudo` or appropriate capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`, potentially `CAP_SYS_ADMIN` for memlock/BPF) is typically required for AF_XDP and eBPF operations.)*

## Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/c3l3si4n/pugdns](https://github.com/c3l3si4n/pugdns)
    cd pugdns
    ```
2.  **Install Dependencies:** Ensure you have Go (>= 1.18 recommended) and Clang/LLVM (for eBPF compilation) installed. You may also need kernel headers (`linux-headers-$(uname -r)` on Debian/Ubuntu).
3.  **Generate eBPF code and Build:**
    ```bash
    go generate && go build
    ```
    This command first compiles the eBPF C code (`pugdns.c`) into an object file using `clang`, then embeds it into a Go file (`pugdns_bpf*.go`) using `bpf2go`, and finally builds the main Go application (`pugdns`).
4.  **Run:**
    ```bash
    sudo ./pugdns [flags...]
    ```

## Credits

-   [cilium/ebpf](https://github.com/cilium/ebpf) - Core eBPF library for Go used for loading and interacting with BPF programs and maps.
-   [slavc/xdp](https://github.com/slavc/xdp) - AF_XDP library for Go
-   Libraries used for UI: `charmbracelet/bubbletea`, `charmbracelet/lipgloss`, `charmbracelet/bubbles`.

---

Feel free to open issues for bugs, feature requests, or questions! Contributions are welcome.
