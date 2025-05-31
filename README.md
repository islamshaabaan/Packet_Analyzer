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

This will create the executable:

```
packet_analyzer
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
sudo ./packet_analyzer -i eth0 -f "tcp"
```

---

## 📊 Output

Statistics are printed every 5 seconds, and include:

- Total packets captured
- Count and % of TCP, UDP, ICMP, Other
- Memory usage in KB


Packet Analyzer (E-VAS Tel Team)
---------------------------------
Interface: wlp3s0
Buffer Size: 100 packets
Filter: none
Duration: 40 seconds
Output File: none

^C
Received signal 2, shutting down...

Final Statistics:
[33 seconds elapsed]
Packets captured: 2782
TCP:   2359 (84.8%)
UDP:   421 (15.1%)
ICMP:  0 (0.0%)
Other: 2 (0.1%)
Memory usage: 28.8 KB

Packet analyzer terminated.
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