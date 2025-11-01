# Network Sniffing and Spoofing Tools

This folder contains a collection of Python-based network tools that includes sending pings, tracerouting, stealing Telnet passwords and perfomring Man in the Middle Attack (ARP poisoning). Only run the repos in controlled environments like VMs where you have control over the netwrok! Or else you can get into legal problems!

## Requirements

- Python 3.x
- Scapy library
- Root/administrator privileges (for raw socket access)

**Installation:**
```bash
pip install scapy --break-system-packages
```

## Tools Overview

### 1. ping.py
Custom ICMP ping implementation that sends echo requests to a target host.

**Usage:**
```bash
sudo python3 ping.py <host>
sudo python3 ping.py google.com
sudo python3 ping.py 8.8.8.8
```

**Features:**
- Resolves domain names to IP addresses
- Displays RTT (Round Trip Time) statistics
- Shows packet loss percentage

### 2. icmp_traceroute.py
Traceroute implementation using ICMP packets to map the network path to a destination.

**Usage:**
```bash
sudo python3 icmp_traceroute.py google.com
sudo python3 icmp_traceroute.py 8.8.8.8 --max-hops 30 --timeout 2.0 --probes 3
```

**Options:**
- `--max-hops`: Maximum TTL to try (default: 30)
- `--timeout`: Timeout per probe in seconds (default: 2.0)
- `--probes`: Number of probes per hop (default: 3)
- `--pause`: Pause between probes
- `--no-dns`: Disable reverse DNS lookups
- `--stop-on-dst-src`: Stop when reply source equals destination. This is mainly a workaround for Windows: whenever an ICMP ping is sent to a destination with ttl=1, Windows intercepts the packet and immediately returns a reply with a IP source address of the destination.

### 3. telnet_sniffer.py
Packet sniffer that captures and displays Telnet keystrokes in real-time.

**Usage:**
```bash
sudo python3 telnet_sniffer.py
```

**Features:**
- Filters TCP port 23 (Telnet) traffic
- Extracts printable characters from captured packets
- Handles Telnet IAC sequences and ANSI escape codes
- Tracks single flow to avoid duplicate echoes
- Displays credentials as they're typed

### 4. arp_mitm.py
Package for ARP poisoning and Man-in-the-Middle (MiTM) attacks. Only run for controlled environmens!

**Usage:**
```bash
sudo python3 arp_mitm.py
```

**Prerequisites:**
- Update MAC addresses and interface names in the script
- Run in a containerized/VM lab environment
- Requires root privileges

**Features:**
1. ICMP ping spoofing to create ARP entries
2. ARP reply spoofing to poison ARP tables
3. Full MiTM attack setup between two hosts
4. Integrated Telnet credential sniffing
5. Interactive menu for step-by-step execution

**Configuration:**
Before running, update these variables in the script:
- `HOST_A_IP`, `HOST_B_IP`, `ATTACKER_IP`
- `HOST_A_MAC`, `HOST_B_MAC`, `ATTACKER_MAC`
- `INTERFACE` (use `ifconfig` to find your interface)

## General Usage Notes

- All tools require root/sudo privileges for raw socket access
- Tools are designed for Unix-like systems (Linux, macOS)
- Windows support varies by tool (see individual tool notes)