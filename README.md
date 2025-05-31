# Packet Analyzer

A network packet analyzer that captures and classifies packets by protocol type (TCP, UDP, ICMP, Other).

## Features
- Real-time packet capture from network interfaces
- Protocol classification and statistics
- Customizable filters using BPF syntax
- Precise 5-second statistics updates
- Memory usage monitoring

## Prerequisites
- Linux environment (tested on Ubuntu WSL)
- libpcap development libraries
- GCC compiler
- Root privileges (for packet capture)

## 🔧 Build Instructions
### 1. Install dependencies:
```bash
sudo apt update
sudo apt install git gcc libpcap-dev
```

### 🏗 Build the Program

Use `make` to compile:

```bash
make
```

This will create the executable:

```
packet_analyzer
```

### 🏗 Run the unit tests

```bash
make test_parser
```

This include:

```
- Basic protocol identification (TCP/UDP/ICMP)
- Edge case handling (malformed packets)

```

---

## ▶️ Run the Program

Basic usage:

```bash
sudo ./packet_analyzer -i <interface> [-f <filter>] [-t <seconds>]
```

### ✅ Optional Flags:

| Flag       | Description                                |
|------------|--------------------------------------------|
| `-i`       | Network interface (e.g. `lo`, `eth0`) **[required]** |
| `-f`       | Optional BPF filter (e.g. `"tcp port 80"`) |
| `-t`       | Optional Duration in seconds (e.g. `-t 30`)         |

---

### 🧪 Examples

Run on loopback for 10 seconds:
```bash
sudo ./packet_analyzer -i lo -t 10
```

Run on Ethernet with TCP filter:
```bash
sudo ./packet_analyzer -i eth0 -f "tcp" -t 40
```

---

## 📊 Output

Statistics are printed every 5 seconds, and include:

- Total packets captured
- Count and % of TCP, UDP, ICMP, Other
- Memory usage in KB


## 📊 Sample Output

```
Packet Analyzer (E-VAS TEL Team)
================================
Interface: eth0
Buffer Size: 8192 packets
Filter: tcp
Duration: 40 seconds
Output File: none
```

Every 5 seconds, the tool prints live statistics like:

```
Packets captured: 134
TCP:   100 (74.6%)
UDP:   30 (22.4%)
ICMP:  3 (2.2%)
Other: 1 (0.7%)
Memory usage: 845.7 KB
=======================
```

At the end of duration or press CTRL+C , a final summary is printed:

```
^C
Received signal 2, shutting down...

Final Statistics:
[42 seconds elapsed]
Packets captured: 358
TCP:   240 (67.0%)
UDP:   90 (25.1%)
ICMP:  21 (5.9%)
Other: 7 (2.0%)
Memory usage: 1124.0 KB

Packet analyzer terminated.
```
---

## 🧼 Clean Up

To remove compiled files:

```bash
make clean
```

---

## 🧠 Notes

- Run with `sudo` to allow packet capture.
- Tested on WSL2 Ubuntu, and standard Linux distros.
- Uses `pcap_dispatch()` for performance.
- Thread-safe counters using atomic operations.
- Validates headers before accessing memory.
- No dynamic memory used → leak-free by design.

---

© 2025 E-VAS Tel Team – Junior Engineer Submission by Islam Shaaban