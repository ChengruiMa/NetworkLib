# Network Programming & Security Projects

A comprehensive collection of network programming implementations and security tools built from scratch to understand networking internals, protocols, security concepts, and wireless communications. These projects implement low-level network operations, protocol implementations, reconnaissance techniques, and physical layer security.

> **Legal Notice**: Security and reconnaissance tools should only be used in controlled environments (VMs, lab networks, owned hardware) where you have explicit written permission. Unauthorized use may be illegal and unethical. Some jurisdictions also regulate wireless signal transmission.

## Project Structure

```
.
├── networkLib/
│   ├── layers.py              # Protocol implementations (Ether, IP, TCP, UDP, ICMP, DNS)
│   ├── network_functions.py   # Transmission functions (send, sendp, sr, sniff)
│   └── tester.py              # Comprehensive test suite
│
├── serverClient/
│   ├── web_server.py          # Single-threaded HTTP server
│   ├── multiThread_server.py  # Multi-threaded HTTP server
│   └── web_client.py          # Custom HTTP client
│
├── sniffSpoof/
│   ├── ping.py                # ICMP ping with statistics
│   ├── icmp_traceroute.py     # Path tracing tool
│   ├── telnet_sniffer.py      # Credential capture tool
│   └── arp_mitm.py            # ARP poisoning framework
│
├── netScan_cryptanalysis/
│   ├── docker-compose.yml     # Lab environment configuration
│   ├── volumes/
│   │   ├── ping_sweep.py      # Network host discovery
│   │   ├── port_scan.py       # TCP SYN port scanner
│   │   ├── crack_password.py  # HTTP brute force tool
│   │   └── count_freq.py      # Frequency analysis tool
│   └── scanner/, server-b/, server-c/  # Dockerfiles
│
├── rssiSecurity/
│   ├── set_monitor_mode.sh    # Monitor mode configuration
│   ├── survivor.py            # Beacon transmitter
│   ├── rescuer.py             # Beacon detector with GUI
│   └── secretKey.py           # RSSI-based key exchange
│
└── README.md                  # This file
```

---


## Requirements

### Software Dependencies
```bash
# For packet library and HTTP tools (no external dependencies)
python3

# For sniffing/spoofing tools
pip install scapy

# For netScan tools
pip install scapy requests numpy

# For wireless tools
pip install scapy numpy
sudo apt-get install wireless-tools iw python3-curses

# Docker for netScan lab environment
sudo apt-get install docker.io docker-compose
```

### System Requirements
- **OS:** Linux (recommended) and macOS (partial support)
- **Python:** 3.6+
- **Privileges:** Root/sudo for raw socket operations
- **Hardware:** Wi-Fi adapter with monitor mode (for wireless tools only)

### Permissions
Most tools require elevated privileges:
```bash
# Run with sudo
sudo python3 tool.py

# Or switch to root
sudo su
python3 tool.py
```

---

## Quick Start Guide

### 1. Network Packet Library - ICMP Ping
```bash
cd networkLib
sudo python3 tester.py
# Test 1: Demonstrates ICMP ping using custom packet construction
```

### 2. HTTP Server & Client
```bash
cd serveClient

# Terminal 1: Start server
python3 multiThread_server.py

# Terminal 2: Test with client
python3 web_client.py localhost 1769 helloworld.html
```

### 3. Network Sniffing - Custom Ping
```bash
cd sniffSpoof
sudo python3 ping.py google.com
# Shows custom ICMP implementation with RTT stats
```

### 4. Network Scanning - Docker Environment
```bash
cd netScan_cryptanalysis

# Start isolated lab environment
docker-compose up -d

# Access scanner container
docker exec -it host-a bash
cd /root/volumes

# Run ping sweep
python3 ping_sweep.py 192.168.60.0/24

# Run port scan
python3 port_scan.py 192.168.60.5 1-1024
```

### 5. Wireless Tools - Key Exchange
```bash
cd rssiSecurity

# Set monitor mode
sudo ./set_monitor_mode.sh wlan0 6

# Device 1
sudo python3 secretKey.py

# Device 2 (simultaneously on another machine)
sudo python3 secretKey.py
```

---

## Current Status

Currently implementing **simulated network routing protocols** to expand the protocol suite and demonstrate dynamic routing mechanisms.

## Projects Overview

### 1. Network Packet Library
Custom packet construction and transmission library similar to Scapy, built from scratch to understand network protocol internals.

**Key Features:**
- Layer 2-7 protocol implementations (Ethernet, IP, ICMP, TCP, UDP, DNS)
- Scapy-style packet stacking with `/` operator
- Raw socket transmission at different OSI layers (send, sendp, sr)
- Packet parsing and construction with automatic checksum calculation
- No external dependencies (pure Python + standard library)

**Supported Protocols:**
- **Layer 2:** Ethernet frames with MAC addressing
- **Layer 3:** IPv4 with automatic header checksum
- **Layer 4:** TCP (full handshake support), UDP, ICMP
- **Layer 7:** DNS queries and response parsing

[View detailed documentation →](./networkLib/)

---

### 2. HTTP Server & Client
Single-threaded and multi-threaded HTTP server implementations with a custom TCP-based client.

**Key Features:**
- Basic HTTP/1.1 server (single-threaded, sequential request handling)
- Multi-threaded server for concurrent connections using Python threading
- Custom HTTP client using raw TCP sockets
- Static file serving with proper HTTP status codes (200 OK, 404 Not Found)
- Connection logging with request tracking


[View detailed documentation →](./serverClient/)

---

### 3. Network Sniffing & Spoofing Tools
Collection of network analysis and security testing tools using Scapy for packet manipulation.

**Tools Included:**
- **ping.py** - Custom ICMP ping implementation with RTT statistics
- **icmp_traceroute.py** - Network path tracing using ICMP TTL manipulation
- **telnet_sniffer.py** - Packet sniffer for capturing Telnet credentials in real-time
- **arp_mitm.py** - ARP poisoning and Man-in-the-Middle attack framework

**Key Features:**
- Packet sniffing with promiscuous mode
- ICMP protocol manipulation
- ARP cache poisoning techniques
- Network reconnaissance methods

**Security Notice:** Only run this on networks that you have explicit control of.

[View detailed documentation →](./sniffSpoof/)

---

### 4. Network Reconnaissance & Security Tools (netScan)
Comprehensive security toolkit for network scanning, password cracking, and cryptanalysis with Docker-based lab environment.

**Tools Included:**
- **ping_sweep.py** - ICMP-based network host discovery with CIDR support
- **port_scan.py** - TCP SYN stealth port scanner with flexible port ranges
- **crack_password.py** - HTTP POST brute force password cracker using dictionary attacks
- **count_freq.py** - Frequency analysis tool for breaking substitution ciphers

**Docker Lab Environment:**
- Isolated 192.168.60.0/24 network with bridge networking
- Three-host setup: scanner (host-a), two target servers (host-b, host-c)
- Pre-configured services for safe penetration testing practice

[View detailed documentation →](./netScan_cryptanalysis/)

---

### 5. Wireless Security & RSSI Tools (rssiSecurity)
Wireless networking tools demonstrating monitor mode operations, custom 802.11 frame transmission, and RSSI-based cryptographic key exchange.

**Tools Included:**
- **set_monitor_mode.sh** - Bash script for configuring wireless interfaces in monitor mode
- **survivor.py** - Custom 802.11 beacon transmitter for emergency signaling
- **rescuer.py** - Real-time beacon detector with ncurses GUI and RSSI visualization
- **secretKey.py** - RSSI-based symmetric key exchange using physical layer security

**Key Features:**
- IEEE 802.11 frame manipulation (RadioTap headers, beacon frames)
- Monitor mode wireless operations
- RSSI (Received Signal Strength Indicator) measurement and analysis
- Physical layer cryptographic key generation
- Channel reciprocity exploitation

**Hardware Requirements:**
- Wi-Fi adapter with monitor mode support (Atheros AR9271, Ralink RT3070/RT5370 recommended)

[View detailed documentation →](./rssiSecurity/)
