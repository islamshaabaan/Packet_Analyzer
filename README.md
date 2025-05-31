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

## Installation

### 1. Install dependencies:
```bash
sudo apt update
sudo apt install git gcc libpcap-dev