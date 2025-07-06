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
Benchmark 1: cat b.txt | dnsx -retry 5 -r resolvers.txt
  Time (mean ± σ):     19.744 s ±  0.086 s    [User: 2.908 s, System: 3.358 s]
  Range (min … max):   19.634 s … 19.876 s    10 runs
 
Benchmark 2: cat b.txt | zdns A --retries 5 --name-servers @resolvers.txt >/dev/null
  Time (mean ± σ):     19.036 s ±  1.214 s    [User: 4.962 s, System: 2.022 s]
  Range (min … max):   17.385 s … 21.283 s    10 runs
 
Benchmark 3: massdns  -r resolvers.txt -s 12000 -c 5  b.txt  >/dev/null
  Time (mean ± σ):      1.299 s ±  0.243 s    [User: 0.036 s, System: 0.137 s]
  Range (min … max):    1.076 s …  1.583 s    10 runs
 
  Warning: Statistical outliers were detected. Consider re-running this benchmark on a quiet system without any interferences from other programs. It might help to use the '--warmup' or '--prepare' options.
 
Benchmark 4: ./pugdns -interface enp6s0 -nameservers resolvers.txt  -retries 5 -domains b.txt -retry-timeout 500ms -maxbatch 300000  -output /dev/null
  Time (mean ± σ):     776.8 ms ±   7.6 ms    [User: 973.6 ms, System: 603.8 ms]
  Range (min … max):   767.4 ms … 792.5 ms    10 runs
 
Summary
  ./pugdns -interface enp6s0 -nameservers resolvers.txt  -retries 5 -domains b.txt -retry-timeout 500ms -maxbatch 300000  -output /dev/null ran
    1.67 ± 0.31 times faster than massdns  -r resolvers.txt -s 12000 -c 5  b.txt  >/dev/null
   24.50 ± 1.58 times faster than cat b.txt | zdns A --retries 5 --name-servers @resolvers.txt >/dev/null
   25.42 ± 0.27 times faster than cat b.txt | dnsx -retry 5 -r resolvers.txt
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
    git clone https://github.com/c3l3si4n/pugdns
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
