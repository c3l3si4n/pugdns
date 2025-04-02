# pugDNS 🐾
![pugDNS](pug.png)

An experimental high-performance DNS query tool built with **AF_XDP** and **eBPF** for extremely fast and accurate bulk DNS lookups. pugDNS uses an eBPF filter to efficiently capture DNS responses directly in the kernel, complementing its high-speed query injection capabilities.

## Overview

pugDNS is designed for security researchers, network administrators, and penetration testers who need to perform DNS reconnaissance at scale. By leveraging AF_XDP sockets for packet transmission and eBPF for response capturing, pugDNS can send queries and process responses at rates significantly higher than traditional tools, making it ideal for domain discovery, enumeration, and validation tasks.

pugDNS will easily saturate your network link, so it's recommended to use this tool on a server with a high-speed internet connection and appropriate network configuration (e.g., ensuring the gateway MAC is correctly resolved or specified).

## Performance

pugDNS is designed to be as fast as possible. It uses AF_XDP sockets to directly inject DNS queries into the network driver (or kernel, depending on mode), bypassing much of the usual network stack. This allows it to send DNS queries and process responses with significantly better throughput and latency than traditional tools.

The following benchmarks were performed on an AX42 Hetzner server (AMD Ryzen™ 7 PRO 8700GE) with a 1Gbit/s port. Benchmarking pugDNS against other popular DNS tools, we observed the following results using a ~20k domain list:

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

```
Usage of pugdns:
  -domain string
    	Single domain to query (when not using -domains file) (default "google.com")
  -domains string
    	File containing domains to query (one per line)
  -dstmac string
    	Destination MAC address (optional, uses ARP resolution if empty)
  -interface string
    	Network interface to attach to
  -maxbatch int
    	Maximum number of packets to send at once. Default is 128. I suggest not changing this. (default 128)
  -nameservers string
    	File containing nameservers to use (one per line)
  -output string
    	File to save results to (default "results.json")
  -poll int
    	Poll timeout in milliseconds (default 1)
  -queue int
    	The queue on the network interface to attach to
  -retries int
    	Number of retries for each domain (default 3)
  -srcip string
    	Source IP address (optional, uses interface IP if empty)
  -srcmac string
    	Source MAC address (optional, uses interface MAC if empty)
  -verbose
    	Enable verbose output
  -workers int
    	Number of workers to use (default 1)
```

**Example Usage:**

```bash
# Query domains from domains.txt using nameservers from resolvers.txt on interface eth0
sudo ./pugdns -interface eth0 -domains domains.txt -nameservers resolvers.txt -output my_results.json
```
*(Note: Running with `sudo` or appropriate capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`, potentially `CAP_SYS_ADMIN` for memlock/BPF) is typically required for AF_XDP and eBPF operations.)*

## Installing

If you don’t want to build pugdns from source and just want to test it out, simply download the pre-compiled binary from our [Releases page](https://github.com/c3l3si4n/pugdns/releases/). It will be easier and faster.


## Building from source
If you really want to build from source, here's a rough guide on how to do so:

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/c3l3si4n/pugdns](https://github.com/c3l3si4n/pugdns)
    cd pugdns
    ```
2.  **Install Dependencies:** Ensure you have Go (>= 1.18 recommended) and Clang/LLVM (for eBPF compilation) installed. You may also need kernel headers (`linux-headers-$(uname -r)` on Debian/Ubuntu).
    ```
    sudo apt install linux-headers-$(uname -r) llvm libbpf-dev clang; sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm;
    ```
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
