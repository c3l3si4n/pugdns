# pugDNS
An experimental high-performance DNS query tool built with AF_XDP for extremely fast and accurate bulk DNS lookups.  
  
~~Be mindful that this is not ready yet, you need to capture the responses with tcpdump because it won't capture the responses itself. For now, you can view responses to your queries by running a command like the following:~~
~~In the future, you won't need to do that ofc.~~  
  
pugDNS now has beta support for receiving DNS packets using an eBPF filter.

## Overview

pugdns is designed for security researchers, network administrators, and penetration testers who need to perform DNS reconnaissance at scale. By leveraging AF_XDP sockets, pugdns can send DNS queries at rates significantly higher than traditional tools, making it ideal for domain discovery and DNS enumeration tasks.

pugdns will easily saturate your link, so it's recommended to use this tool on a server with a high-speed internet connection.

## Performance

pugdns is designed to be as fast as possible. It uses AF_XDP sockets to directly inject DNS queries into the L2 layer of your kernel. This allows it to create a fast-path through the kernel, bypassing the usual network stack and allowing it to send DNS queries at rates significantly better bandwith and latency than traditional tools.

The following benchmarks were performed on a AX42 Hetzner server with a 1Gbit/s port, with a AMD Ryzen 7 PRO 8700. Benchmarking pugdns against other popular DNS tools, we observed the following results:
- pugdns was ~3.3x faster than massdns
- pugdns was ~12.5x faster than zdns
- pugdns was ~29.6x faster than dnsx

```bash
Benchmark 1: cat wordlist.txt | dnsx -retry 1 -r a.txt
  Time (mean ± σ):      5.530 s ±  0.014 s    [User: 0.870 s, System: 1.002 s]
  Range (min … max):    5.514 s …  5.539 s    3 runs
 
Benchmark 2: cat wordlist.txt | zdns A --retries 1 --name-servers @a.txt >/dev/null
  Time (mean ± σ):      2.350 s ±  0.089 s    [User: 1.979 s, System: 0.659 s]
  Range (min … max):    2.283 s …  2.451 s    3 runs
 
Benchmark 3: massdns  -r a.txt -s 12000 -c 1  wordlist.txt  >/dev/null
  Time (mean ± σ):     616.6 ms ±   4.7 ms    [User: 25.5 ms, System: 107.8 ms]
  Range (min … max):   612.0 ms … 621.3 ms    3 runs
 
Benchmark 4: ./pugdns -interface enp6s0 -domains wordlist.txt -nameservers a.txt
  Time (mean ± σ):     186.6 ms ±   4.3 ms    [User: 33.9 ms, System: 48.7 ms]
  Range (min … max):   181.9 ms … 190.5 ms    3 runs
 
Summary
  ./pugdns -interface enp6s0 -domains wordlist.txt -nameservers a.txt ran
    3.30 ± 0.08 times faster than massdns  -r a.txt -s 12000 -c 1  wordlist.txt  >/dev/null
   12.59 ± 0.56 times faster than cat wordlist.txt | zdns A --retries 1 --name-servers @a.txt >/dev/null
   29.64 ± 0.69 times faster than cat wordlist.txt | dnsx -retry 1 -r a.txt
```

Looking into the accuracy and number of responses that came back, we had the following numbers testing with a 19966 domain wordlist:

| Tool | Accuracy | Number of Responses |
|------|----------|---------------------|
| pugdns | 100% | 19969 |
| massdns | 99.994% | 19968 |
| zdns | 100% | 19969 |
| dnsx | 99.984% | 19966 |


## Features Roadmap
- [x] Add support for AF_XDP raw sockets
- [x] Add support for multiple nameservers and subdomains file as input
- [ ] Add support for sniffing DNS Responses (this is a big TO:DO)

## Installation

```
git clone https://github.com/c3l3si4n/pugdns
go generate && go build
./pugdns
``` 

## Credits
- [slavc/xdp](https://github.com/slavc/xdp) - AF_XDP library for Go
