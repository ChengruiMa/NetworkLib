# Network Packet Library

A from-scratch implementation of network packet construction and transmissions, similar to Scapy but built to understand the internals of network protocols. This library provides classes for creating, parsing, and transmitting network packets at various OSI layers.

## Folder Structure

1. **layers.py** - Network protocol layer implementations
2. **network_functions.py** - Send/receive functions for packet transmission
3. **tester.py** - Comprehensive test suite demonstrating the functionality

## Requirements

- Python 3.x
- Root/sudo privileges (for raw sockets)
- Linux environment (uses AF_PACKET sockets)
- Standard library only (no external dependencies)

## layers.py - Protocol Implementations

### Base Class: PacketBase
Foundation for all protocol layers providing:
- Layer stacking with `/` operator (like Scapy)
- Recursive packet building
- Layer traversal and search
- Pretty-print display functionality

### Implemented Layers

#### Layer 2: Ether (Ethernet)
```python
pkt = Ether(src_mac="aa:bb:cc:dd:ee:ff", dst_mac="11:22:33:44:55:66")
```

**Features:**
- Parse Ethernet frames from raw bytes
- Build Ethernet headers
- Support for EtherType field
- Automatic payload type detection (IPv4)

**Fields:**
- `src_mac`: Source MAC address (string format)
- `dst_mac`: Destination MAC address
- `type`: EtherType (default: 0x0800 for IPv4)

#### Layer 3: IP (Internet Protocol v4)
```python
pkt = IP(src_ip="192.168.1.100", dst_ip="8.8.8.8", ttl=64)
```

**Features:**
- Full IPv4 header construction
- Automatic header checksum calculation
- Protocol field auto-detection from payload
- Total length calculation
- Support for ICMP, TCP, UDP protocols

**Fields:**
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `ttl`: Time to live (default: 64)
- `proto`: Protocol number (1=ICMP, 6=TCP, 17=UDP)
- Automatic: `version`, `ihl`, `checksum`, `total_len`

#### Layer 4: ICMP (Internet Control Message Protocol)
```python
pkt = ICMP(type=8, code=0, id=1234, seq=1)  # Echo Request
```

**Features:**
- ICMP header construction
- Automatic checksum calculation
- Support for echo request/reply

**Fields:**
- `type`: ICMP message type (8=Echo Request, 0=Echo Reply)
- `code`: ICMP code
- `id`: Identifier for matching requests/replies
- `seq`: Sequence number

#### Layer 4: UDP (User Datagram Protocol)
```python
pkt = UDP(sport=12345, dport=53)  # DNS query
```

**Features:**
- UDP header construction
- Automatic checksum with pseudo-header
- Length calculation

**Fields:**
- `sport`: Source port
- `dport`: Destination port
- `src_ip`, `dst_ip`: Required for checksum (auto-set when stacked with IP)

#### Layer 4: TCP (Transmission Control Protocol)
```python
pkt = TCP(sport=50000, dport=80, seq=1000, ack=0, flags=0x002)  # SYN
```

**Features:**
- Full TCP header construction
- Automatic checksum with pseudo-header
- Support for all TCP flags
- Window size management
- Data payload support

**Fields:**
- `sport`: Source port
- `dport`: Destination port
- `seq`: Sequence number
- `ack`: Acknowledgment number
- `flags`: TCP flags (0x002=SYN, 0x010=ACK, 0x018=PSH+ACK, etc.)
- `window`: Window size
- `data`: Optional data payload

**TCP Flags:**
```python
SYN = 0x002      # Synchronize
ACK = 0x010      # Acknowledgment
PSH = 0x008      # Push
FIN = 0x001      # Finish
RST = 0x004      # Reset
SYN_ACK = 0x012  # SYN + ACK
PSH_ACK = 0x018  # PSH + ACK
FIN_ACK = 0x011  # FIN + ACK
```

#### Layer 7: DNS (Domain Name System)
```python
# DNS Query
pkt = DNS(qname="example.com", qtype=1, qclass=1)

# Parse DNS Response
response = DNS(raw_bytes=data)
print(response.addr)  # Resolved IP address
```

**Features:**
- DNS query construction
- DNS response parsing
- Support for A record queries (IPv4)
- Question and answer section handling

**Fields:**
- `qname`: Domain name to query
- `qtype`: Query type (1=A record)
- `qclass`: Query class (1=IN - Internet)
- `id`: Transaction ID (auto-generated)

### Layer Stacking

Use the `/` operator to stack layers (Scapy-style):

```python
# ICMP Ping
pkt = IP(src_ip="192.168.1.100", dst_ip="8.8.8.8") / ICMP(type=8, seq=1)

# DNS Query over UDP
pkt = IP(src_ip="192.168.1.100", dst_ip="8.8.8.8") / \
      UDP(sport=50000, dport=53) / \
      DNS(qname="google.com")

# Full Layer 2 to Layer 7 stack
pkt = Ether(src_mac=my_mac, dst_mac=gateway_mac) / \
      IP(src_ip=my_ip, dst_ip="8.8.8.8") / \
      TCP(sport=50000, dport=80, flags=0x002)
```

### Packet Operations

```python
# Display packet structure
pkt.show()

# Build packet bytes
packet_bytes = pkt.build()

# Get specific layer
ip_layer = pkt.get_layer('IP')
tcp_layer = pkt.get_layer('TCP')

# Parse from raw bytes
received_pkt = Ether(raw_bytes=data)
```

## network_functions.py - Transmission for Packets

### send(pkt)
Send packet at **Layer 3** (IP layer) using raw sockets.

```python
# Send IP packet (Ethernet header will be added by OS)
pkt = IP(src_ip="192.168.1.100", dst_ip="8.8.8.8") / ICMP(type=8, seq=1)
send(pkt)
```

**Use when:**
- Letting the OS handle Layer 2
- Don't need to control MAC addresses
- Working with IP and above

### sendp(pkt, interface)
Send packet at **Layer 2** (Ethernet layer) using raw sockets.

```python
# Send complete Ethernet frame
pkt = Ether(src_mac=my_mac, dst_mac=gateway_mac) / \
      IP(src_ip=my_ip, dst_ip="8.8.8.8") / \
      ICMP(type=8, seq=1)
sendp(pkt, "eth0")
```

**Use when:**
- Need full control over Layer 2
- Specifying MAC addresses
- Network analysis or testing

### sr(pkt, timeout=5)
**Send and Receive** - Send packet at Layer 3 and wait for reply at Layer 2.

```python
# Send ICMP ping and wait for reply
pkt = IP(src_ip=my_ip, dst_ip="8.8.8.8") / ICMP(type=8, seq=1)
reply = sr(pkt, timeout=5)

if reply:
    reply.show()  # Display received packet
else:
    print("No reply received")
```

**Features:**
- Automatically filters replies based on IP addresses
- Returns first matching packet
- Useful for request-response protocols (ICMP, DNS, etc.)

### sniff(timeout=None)
Receive one packet at Layer 2.

```python
# Capture one packet
pkt = sniff(timeout=10)
if pkt:
    pkt.show()
```

**Use when:**
- Passively monitoring network traffic
- Waiting for specific packets
- Implementing packet capture tools

## tester.py

Testing of library capabilities with three major tests:

### Test 1: ICMP Ping
Tests all three transmission methods:
- `send()` - Layer 3 transmission
- `sendp()` - Layer 2 transmission
- `sr()` - Send and receive with reply matching

### Test 2: DNS Query
Demonstrates DNS A record lookup:
- Constructs DNS query packet
- Sends over UDP
- Parses DNS response
- Extracts resolved IP address

### Test 3: TCP HTTP GET
Full TCP three-way handshake and HTTP request:
1. **SYN** - Initiate connection
2. **ACK** - Complete handshake
3. **HTTP GET** - Send request with PSH+ACK
4. **Receive Response** - Handle multiple data packets
5. **FIN-ACK** - Graceful connection close

**Special Handling:**
- Adds iptables rule to prevent kernel RST packets
- Automatic ACK for received data segments
- Multi-packet response handling
- Proper connection teardown

### Running Tests

```bash
# Run all tests interactively
sudo python3 tester.py

# Tests will pause between sections for observation
# Monitor with Wireshark for packet-level verification
```

**Test Output:**
- Network configuration detection
- Packet structure visualization
- Transmission confirmations
- Reply packet details
- HTTP response content

## Usage Examples

### Example 1: Simple ICMP Ping
```python
from layers import *
from network_functions import *

# Create packet
pkt = IP(src_ip="192.168.1.100", dst_ip="8.8.8.8") / ICMP(type=8, id=1234, seq=1)

# Send and wait for reply
reply = sr(pkt, timeout=5)

if reply:
    icmp = reply.get_layer('ICMP')
    if icmp and icmp.type == 0:  # Echo Reply
        print("Ping successful!")
```

### Example 2: DNS Lookup
```python
from layers import *
from network_functions import *

# Build DNS query
pkt = IP(src_ip="192.168.1.100", dst_ip="8.8.8.8") / \
      UDP(sport=50000, dport=53) / \
      DNS(qname="google.com", qtype=1)

# Send query and get response
reply = sr(pkt, timeout=5)

if reply:
    dns = reply.get_layer('DNS')
    if dns and hasattr(dns, 'addr'):
        print(f"Resolved: {dns.addr}")
```

### Example 3: TCP SYN Scan
```python
from layers import *
from network_functions import *

# Send SYN packet
pkt = IP(src_ip="192.168.1.100", dst_ip="192.168.1.1") / \
      TCP(sport=50000, dport=80, flags=0x002)  # SYN flag

# Check for SYN-ACK reply
reply = sr(pkt, timeout=3)

if reply:
    tcp = reply.get_layer('TCP')
    if tcp and tcp.flags & 0x012 == 0x012:  # SYN-ACK
        print("Port 80 is open")
```

## Technical Implementation Details

### Checksum Calculation
Both IP and TCP/UDP use Internet checksum (RFC 1071):
- Sum 16-bit words with carries
- One's complement of the result
- TCP/UDP include pseudo-header for checksum

### TCP Pseudo-Header
```
+--------+--------+--------+--------+
|          Source Address           |
+--------+--------+--------+--------+
|        Destination Address        |
+--------+--------+--------+--------+
|  zero  |  PTCL  |    TCP Length   |
+--------+--------+--------+--------+
```

### Packet Building Process
1. Build payload layers recursively
2. Calculate lengths bottom-up
3. Compute checksums with complete data
4. Assemble final packet bytes
