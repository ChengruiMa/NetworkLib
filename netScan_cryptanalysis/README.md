# Network Reconnaissance & Security Tools

A collection of network security and reconnaissance tools for various attack techniques including network scanning, password cracking, and cryptanalysis. Built for educational purposes on network security. Only use the library on networks, systems, and devices you own or have explicit written permission to test.

## Project Overview

This toolkit contains four interconnected security tools:

1. **ping_sweep.py** - Network host discovery via ICMP
2. **port_scan.py** - TCP port scanning with SYN packets
3. **crack_password.py** - HTTP POST brute force attack
4. **count_freq.py** - Frequency analysis for substitution ciphers


## Requirements

### Docker Compose Setup

This folder uses Docker containers to create an isolated network environment for safe testing. The `docker-compose.yml` file defines three hosts on a custom bridge network.

**Network Architecture:**
```
192.168.60.0/24 subnet (br-cs60 bridge)
├─ 192.168.60.1   - Gateway (host VM)
├─ 192.168.60.2   - host-a (scanner container)
├─ 192.168.60.5   - host-b (target server)
└─ 192.168.60.X   - host-c (target server)
```

**Container Roles:**

1. **host-a (Scanner)**: Attacker/reconnaissance machine
   - Contains scanning tools
   - Volume mounted: `./volumes` → `/root/volumes`
   - Capabilities: `NET_RAW`, `NET_ADMIN` (for raw sockets)
   - Alias: `scanner`, `hosta`

2. **host-b (Target Server B)**: Web server target
   - Port 60: Custom login service (password cracking target)
   - Port 80: Web service
   - Capability: `NET_BIND_SERVICE`

3. **host-c (Target Server C)**: Additional target
   - Additional services for scanning
   - Capability: `NET_BIND_SERVICE`

**Starting the Lab Environment:**

```bash
# Start all containers
docker-compose up -d

# Verify containers are running
docker ps

# Check network configuration
docker network inspect labnet

# Access scanner container (host-a)
docker exec -it host-a bash

# Access from host VM (for wireless tools)
# Your host VM is 192.168.60.1
```

**Network Configuration Details:**

```yaml
networks:
  labnet:
    driver: bridge
    driver_opts:
      com.docker.network.bridge.name: br-cs60
    ipam:
      config:
        - subnet: 192.168.60.0/24
          gateway: 192.168.60.1
    attachable: true
```

- **Bridge name**: `br-cs60` (visible on host with `ip link`)
- **Subnet**: 192.168.60.0/24 (254 usable addresses)
- **Gateway**: 192.168.60.1 (host VM)
- **Attachable**: Allows external containers to join

**Working Directory Structure:**

```
project/
├── docker-compose.yml
├── scanner/              # Dockerfile for host-a
│   └── Dockerfile
├── server-b/             # Dockerfile for host-b
│   └── Dockerfile
├── server-c/             # Dockerfile for host-c
│   └── Dockerfile
└── volumes/              # Shared files
    ├── ping_sweep.py
    ├── port_scan.py
    ├── crack_password.py
    ├── english_words.txt
    └── ...
```

**Container Management:**

```bash
# Start environment
docker-compose up -d

# Stop environment
docker-compose down

# Rebuild after Dockerfile changes
docker-compose build
docker-compose up -d

# View logs
docker-compose logs -f host-a

# Remove everything (including volumes)
docker-compose down -v
```

## Other Requirements

### Software Dependencies

```bash
# Install Python packages
pip install scapy requests numpy

# Install system utilities (Debian/Ubuntu)
sudo apt-get install wireless-tools iw

# Install Docker (if not already installed)
sudo apt-get install docker.io docker-compose
sudo usermod -aG docker $USER  # Add user to docker group
# Log out and back in for group changes to take effect
```

### Docker Lab Environment (Quick Start)

The included `docker-compose.yml` creates an isolated network for safe testing:

```bash
# Start the lab (3 hosts on 192.168.60.0/24)
docker-compose up -d

# Access scanner host
docker exec -it host-a bash
cd /root/volumes

# Run tools safely within isolated network
python3 ping_sweep.py 192.168.60.0/24
python3 port_scan.py 192.168.60.2 1-1024
python3 crack_password.py

# Stop the lab
docker-compose down
```

**Network:** 192.168.60.0/24 | **Gateway:** 192.168.60.1 | **Containers:** host-a (scanner), host-b/c (targets)

See the "Docker Lab Environment" section below for complete details.

### Python Version
- **Required**: Python 3.6+
- **Tested on**: Python 3.8-3.11

### Permissions
Most tools require elevated privileges:
```bash
# Run with sudo
sudo python3 ping_sweep.py 192.168.60.0/24

# Or switch to root
sudo su
python3 port_scan.py 192.168.60.5 1-1024
```


### Software Dependencies

```bash
# Install Python packages
pip install scapy requests numpy

# Install system utilities (Debian/Ubuntu)
sudo apt-get install wireless-tools iw
```

### Python Version
- **Required**: Python 3.6+

### Permissions
Most tools require root privileges:
```bash
# Run with sudo
sudo python3 ping_sweep.py 192.168.60.0/24

# Or switch to root
sudo su
python3 port_scan.py 192.168.60.5 1-1024
```

### Required Files

Create these files in the same directory:

**english_words.txt** (for crack_password.py):
```bash
# Option 1: System dictionary
cat /usr/share/dict/words > english_words.txt

# Option 2: Download wordlist
wget https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt -O english_words.txt

# Option 3: Create custom list
nano english_words.txt
# Add one password per line:
password
123456
admin
letmein
```

**cipher.txt** (for count_freq.py):
```bash
echo "ylu krhldyl muxxcbu rx..." > cipher.txt
```

---
## Tool Documentation

### 1. ping_sweep.py

Discovers active hosts on a network by sending ICMP echo requests (pings) to each address in a subnet. This is a network reconnaissance technique to identify which IP addresses in a subnet are assigned to active hosts. It's the essential first step in penetration testing.

**Usage:**
```bash
python3 ping_sweep.py <subnet_in_CIDR_format>
```

**Examples:**
```bash
# Scan entire /24 network (254 hosts)
python3 ping_sweep.py 192.168.60.0/24

# Scan smaller /28 network (14 hosts)
python3 ping_sweep.py 10.0.0.0/28

# Scan /16 network (65,534 hosts - may take a while!)
python3 ping_sweep.py 172.16.0.0/16
```

**How It Works:**
1. Parse CIDR notation to get network range
2. Generate list of all host IPs (excludes .0 and .255)
3. Create thread pool (50 concurrent workers)
4. Send ICMP echo request to each host
5. Wait up to 1 second for reply
6. Collect and sort responsive hosts

**Output Example:**
```
Starting ping sweep on 192.168.60.0/24
==================================================
Scanning 254 hosts in subnet 192.168.60.0/24
Range: 192.168.60.1 - 192.168.60.254
--------------------------------------------------
[+] 192.168.60.1 is UP
[+] 192.168.60.2 is UP
[+] 192.168.60.5 is UP

==================================================
Scan complete. Found 3 active host(s):
--------------------------------------------------
192.168.60.1
192.168.60.2
192.168.60.5
==================================================
```

**CIDR Quick Reference:**
```
/24 = 256 addresses (254 usable)   - Class C network
/28 = 16 addresses (14 usable)     - Small subnet
/29 = 8 addresses (6 usable)       - Tiny subnet
/30 = 4 addresses (2 usable)       - Point-to-point link
/16 = 65,536 addresses             - Class B network
```

**Use Cases:**
- Initial network reconnaissance
- Network inventory and documentation
- Identifying unauthorized devices

---

### 2. port_scan.py

Discovers open TCP ports on a host by sending SYN packets. This port scanning tool identifies which network services are running on a host. Uses TCP SYN scanning (stealth scan) which doesn't complete the three-way handshake, making it harder to detect than full connection scans.

**Usage:**
```bash
python3 port_scan.py <ip_address> <port_range>
```

**Examples:**
```bash
# Scan common ports
python3 port_scan.py 192.168.60.5 1-1024

# Scan specific ports
python3 port_scan.py 192.168.60.5 22,80,443,8080

# Scan ranges and specific ports
python3 port_scan.py 192.168.60.5 1-100,200-300,8080,9000-9010

# Scan all ports (warning: slow!)
python3 port_scan.py 192.168.60.5 1-65535
```

**Port Range Format:**
- **Single port**: `80`
- **Range**: `1-1024` (inclusive)
- **Multiple**: `22,80,443` (comma-separated)
- **Combined**: `1-1024,8080,9000-9010`

**How It Works (SYN Scan):**
```
1. Client → Server: SYN packet
   ↓
2. Server → Client: 
   - SYN-ACK = Port OPEN
   - RST-ACK = Port CLOSED
   - No response = Port FILTERED
   ↓
3. Client → Server: RST (immediately close)
```

This never completes the TCP handshake, so it's considered "stealthier" than a full connection scan.

**Output Example:**
```
Starting port scan on 192.168.60.5
Ports to scan: 1024
==================================================
Scanning 1024 port(s) on 192.168.60.5
--------------------------------------------------
[+] Port 22/tcp is OPEN
[+] Port 60/tcp is OPEN
[+] Port 80/tcp is OPEN
Progress: 100/1024 ports scanned...
Progress: 200/1024 ports scanned...
...

==================================================
Scan complete. Found 3 open port(s):
--------------------------------------------------
Port 22/tcp
Port 60/tcp
Port 80/tcp
==================================================
```

**Common Ports:**
```
20/21   - FTP (File Transfer)
22      - SSH (Secure Shell)
23      - Telnet (Insecure remote access)
25      - SMTP (Email)
53      - DNS
60      - Custom (Lab-specific)
80      - HTTP (Web)
110     - POP3 (Email)
143     - IMAP (Email)
443     - HTTPS (Secure web)
3306    - MySQL
3389    - RDP (Remote Desktop)
5432    - PostgreSQL
8080    - HTTP Alternate
```

---

### 3. crack_password.py

Brute force password cracker for HTTP POST login forms using dictionary attacks. The code attempts to authenticate to a web application by systematically trying every password in a dictionary file. It demonstrates the importance of rate limiting and account lockout mechanisms.

**Usage:**
```bash
python3 crack_password.py
```

**Configuration (Edit in script):**
```python
TARGET_HOST = "192.168.60.2"      # Target IP address
TARGET_PORT = 60                   # Target port
ID = "*"                            # Username to test
DICTIONARY_FILE = "./english_words.txt"  # Password list
```

**How It Works:**
1. Load dictionary file (english_words.txt)
2. For each password in dictionary:
   - Send HTTP POST to /login endpoint
   - Include username and password
   - Check response for success indicators
3. If "Login failed" not in response → Success!
4. Report findings with statistics

**HTTP Request Structure Assumptions:**
```http
POST /login HTTP/1.1
Host: 192.168.60.2:60
Content-Type: application/x-www-form-urlencoded

username=your_username&password=testpassword          # Change the code up accordingly with the website's HTTP content
```

**Output Example:**
```
BRUTE FORCING PASSWORDS
======================================================================
HTTP POST PASSWORD CRACKER
======================================================================

Target:     http://192.168.60.2:60/login
Username:   your_username
Dictionary: ./english_words.txt
Method:     POST (observed in Wireshark)
======================================================================

Loaded 235886 passwords

Testing Password: aardvark
Response:<Response [200]>
Login Failed

Testing Password: abandon
Response:<Response [200]>
Login Failed

...

Testing Password: password123
Response:<Response [200]>

======================================================================
SUCCESS! PASSWORD FOUND!
======================================================================
Password:       password123
Attempts:       15234/235886
Response code:  200
Response size:  1523 bytes
======================================================================
```

**Dictionary File (english_words.txt):**
The script requires a dictionary file with one password per line. Create this file:

```bash
# Option 1: Use system dictionary
cat /usr/share/dict/words > english_words.txt

# Option 2: Download common passwords list
wget https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -O english_words.txt

# Option 3: Create custom list
echo "password" > english_words.txt
echo "123456" >> english_words.txt
echo "admin" >> english_words.txt
```
---

### 4. count_freq.py

Frequency analysis tool for breaking monoalphabetic substitution ciphers. Substitution ciphers replace each letter with another letter consistently. Since English has predictable letter frequencies (E, T, A, O are most common), analyzing ciphertext frequencies can reveal the mapping.

**Usage:**
```bash
python3 count_freq.py
```

**How It Works:**
1. Read ciphertext from `cipher.txt`
2. Count frequency of each letter (case-insensitive)
3. Sort by frequency (most → least common)
4. Display frequency table
5. Apply substitution map (if defined)
6. Output decrypted text

**Frequency Analysis Approach:**
```
English Letter Frequencies:
E: 12.7%    T: 9.1%     A: 8.2%     O: 7.5%
I: 7.0%     N: 6.7%     S: 6.3%     H: 6.1%

Strategy:
1. Most frequent ciphertext letter likely = 'E'
2. Second most likely = 'T' or 'A'
3. Look for patterns:
   - "THE" is most common 3-letter word
   - "A" and "I" are only single-letter words
   - Common digrams: TH, HE, IN, ER, AN
   - Common trigrams: THE, AND, ING, HER
```

**Substitution Map (Edit in script):**
```python
SUBSTITUTION_MAP = {
    'h': 'E',  # Ciphertext 'h' → Plaintext 'E'
    'y': 'T',  # Ciphertext 'y' → Plaintext 'T'
    'k': 'C',
    'u': 'S',
    # Add more mappings as you discover them
}
```

**Output Example:**
```
[('c', 'A'), ('h', 'E'), ('k', 'C'), ('t', 'N'), ('u', 'S'), ...]
Total letters analyzed: 5432

Character Frequencies (sorted by count):
--------------------------------------------------
Letter     Count      Percentage
--------------------------------------------------
h          687        12.65%
y          492        9.06%
c          445        8.19%
t          364        6.70%
u          342        6.30%
...

==================================================
Applying substitutions:
  u -> S
  h -> E
  k -> C
  y -> T
  ...

======================================================================
DECRYPTED TEXT:
======================================================================
THE SECRET MESSAGE IS SECURITY THROUGH OBSCURITY IS NOT REAL 
SECURITY. ENCRYPTION AND AUTHENTICATION ARE ESSENTIAL FOR 
PROTECTING DATA IN TRANSIT AND AT REST...
```

**Workflow:**
1. Run script to see frequency table
2. Compare to English frequencies
3. Make educated guesses for mappings
4. Add mappings to SUBSTITUTION_MAP
5. Run again to see partial decryption
6. Identify more letters from context
7. Repeat until fully decrypted

**Input File:**
Create `cipher.txt` with your ciphertext:
```
ylu krhldyl quxxcbu rx xukwfryp ylfhwbl hnxkwfryp rx thy fucl...
```