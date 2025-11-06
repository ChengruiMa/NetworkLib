# Wireless Communication, Radio Signal Strength & Security Tools

A collection of wireless networking tools demonstrating monitor mode operations for WLAN, custom beacon frame transmission/detection, and RSSI-based cryptographic key exchange. Built for educational purposes to understand Wi-Fi protocols and physical layer security. Only use these tools on networks and hardware you own or have explicit permission to test, and be cautious that some jurisdictions regulate the transmission of wireless signals.


## Folder Overview

This folder contains four interconnected tools:

1. **set_monitor_mode.sh** - Bash script to configure wireless interfaces
2. **survivor.py** - Custom beacon transmitter for emergency scenarios
3. **rescuer.py** - Beacon detector with RSSI-based localization
4. **secretKey.py** - RSSI-based symmetric key exchange protocol

## Requirements

### Hardware
- **Wi-Fi Adapter**: Must support monitor mode
- **Recommended chipsets**: 
  - Atheros AR9271 (common in USB adapters)
  - Ralink RT3070/RT5370
  - Intel (some models)
- **Check capability**: `iw list | grep monitor`

### Software
```bash
# Install Python dependencies
pip install scapy numpy

# For rescuer.py (ncurses)
sudo apt-get install python3-curses  # If not included

# Verify wireless tools
sudo apt-get install wireless-tools iw
```

### Permissions
All tools require root privileges:
```bash
sudo python3 survivor.py wlan0 6
# or
sudo su
python3 survivor.py wlan0 6
```

## Configuration

### 1. Make scripts executable
```bash
chmod +x set_monitor_mode.sh
```

### 2. Verify wireless interface
```bash
iwconfig                    # List wireless interfaces
iw dev                      # Modern alternative
sudo iw dev wlan0 info      # Check specific interface
```

### 3. Test monitor mode capability
```bash
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
sudo iw dev wlan0 info      # Should show type: monitor
```

### 4. Select appropriate channel
```bash
# 2.4 GHz channels (most common)
Channels 1, 6, 11 - Non-overlapping (recommended for testing)

# 5 GHz channels
Channels 36, 40, 44, 48... (if supported by hardware)
```

## Usage Scenarios

### Scenario 1: Search and Rescue Demo
```bash
# Terminal 1 (Survivor)
sudo python3 survivor.py wlan0 6

# Terminal 2 (Rescuer)
sudo python3 rescuer.py wlan0 6

# Rescuer moves around, observing RSSI changes
# Higher RSSI = closer to survivor
```

### Scenario 2: Key Exchange Between Two Devices
```bash
# Device A
sudo python3 secretKey.py

# Device B (simultaneously)
sudo python3 secretKey.py

# One becomes initiator, one becomes responder automatically
# Both should arrive at the same key
```

## Tools Documentation

### 1. set_monitor_mode.sh

Bash script to configure a Wi-Fi adapter for monitor mode on a specific channel.

**Usage:**
```bash
chmod +x set_monitor_mode.sh
sudo ./set_monitor_mode.sh <interface> <channel>
```

**Example:**
```bash
sudo ./set_monitor_mode.sh wlan0 6
```

**What it does:**
1. Brings the interface down
2. Sets monitor mode with control frames
3. Brings the interface back up
4. Configures the specified channel and verify the configuration

**Common interfaces:**
- `wlan0` - First wireless interface (most common)
- `wlan1` - Second wireless interface
- Check with: `iwconfig` or `ip link show`

**Common channels:**
- 2.4 GHz: Channels 1-11 (US), 1-13 (Europe)
- Channel 6 is often used for testing (center of band)

---

### 2. survivor.py

Transmits custom 802.11 beacon frames containing a unique survivor ID for search and rescue operations.

**Concept:**
Simulates an emergency beacon that continuously broadcasts a unique identifier, allowing rescuers to detect and locate survivors based on signal strength.

**Usage:**
```bash
sudo python3 survivor.py <interface> <channel>
```

**Example:**
```bash
sudo python3 survivor.py wlan0 6
```

**Features:**
- Generates unique survivor ID (1-9999)
- Transmits custom beacon frames at 10 Hz (every 100ms)
- Embeds "RESCUE" magic marker for identification
- Uses custom MAC address encoding (02:00:00:00:XX:YY)
- Includes timestamp and SOS message in payload
- Use RadioTap and IEEE 802.11 frame structure

**Frame Structure:**
```
RadioTap Header (8 bytes)
├─ Version: 0
├─ Padding: 0
├─ Length: 8
└─ Present flags: 0

802.11 Beacon Frame
├─ Frame Control: Management/Beacon (0x0080)
├─ Duration: 0
├─ Destination: Broadcast (FF:FF:FF:FF:FF:FF)
├─ Source: 02:00:00:00:XX:YY (XX:YY = survivor_id)
├─ BSSID: Same as source
├─ Sequence Control: Increments per frame
├─ Timestamp: Microseconds since epoch
├─ Beacon Interval: 100 TUs
├─ Capability Info: ESS
└─ Information Element (Vendor Specific)
    ├─ Element ID: 221
    ├─ Length: Variable
    └─ Payload:
        ├─ Magic: "RESCUE"
        ├─ Survivor ID: 2 bytes
        ├─ Timestamp: 4 bytes
        └─ Message: " SOS - Need Help!"
```

**Output:**
```
SURVIVOR BEACON TRANSMITTER
Survivor ID: 4762
Interface: wlan0
Channel: 6

Transmitting beacon frames... Press Ctrl+C to stop
Rescuers should look for Survivor ID: 4762

Beacons sent: 10 (ID: 4762, Seq: 10)
Beacons sent: 20 (ID: 4762, Seq: 20)
...
```

---

### 3. rescuer.py

Real-time beacon detector with ncurses GUI displaying RSSI values to guide rescue operations.

**Concept:**
Passively monitors for survivor beacon frames and displays signal strength (RSSI) information. As rescuers move closer to survivors, RSSI values increase, so the GUI will give rough directional guidance.

**Usage:**
```bash
sudo python3 rescuer.py <interface> <channel>
```

**Example:**
```bash
sudo python3 rescuer.py wlan0 6
```

**Features:**
- **Multi-survivor detection**: Tracks multiple survivors simultaneously
- **RSSI display**: Shows real-time signal strength in dBm using ncurses
- **Signal strength visualization**: Color-coded bars (Excellent → Very Weak)
- **Distance analysis**: Indicates if getting closer or farther
- **Packet statistics**: Last seen time and total packets received

**RSSI Interpretation:**
```
≥ -50 dBm  ▮▮▮▮▮  Excellent  (Very close - <5m typically)
≥ -60 dBm  ▮▮▮▮▯  Very Good  (Close - 5-10m)
≥ -70 dBm  ▮▮▮▯▯  Good       (Medium - 10-20m)
≥ -80 dBm  ▮▮▯▯▯  Fair       (Far - 20-40m)
≥ -90 dBm  ▮▯▯▯▯  Weak       (Very far - 40-80m)
< -90 dBm  ▯▯▯▯▯  Very Weak  (Extreme distance)
```

**GUI Display:**
```
╔══════════════════════════════════════════════════════════╗
║     SEARCH AND RESCUE - SURVIVOR DETECTOR                ║
╠══════════════════════════════════════════════════════════╣
║  Current Time: 2024-11-06 14:30:45                      ║
║  Survivors Detected: 2                                   ║
║                                                          ║
║  ──────────────────────────────────────────────────────  ║
║  Survivor ID: 4762                                       ║
║    RSSI: -65 dBm   ▮▮▮▮▯ Very Good                      ║
║    Trend: ↑ GETTING CLOSER                               ║
║    Last Seen: 0.2s ago          Packets: 1523           ║
║                                                          ║
║  ──────────────────────────────────────────────────────  ║
║  Survivor ID: 8231                                       ║
║    RSSI: -78 dBm   ▮▮▯▯▯ Fair                           ║
║    Trend: → Stable                                       ║
║    Last Seen: 0.1s ago          Packets: 892            ║
╠══════════════════════════════════════════════════════════╣
║  Press 'q' to quit | Move toward increasing RSSI        ║
╚══════════════════════════════════════════════════════════╝
```

**Trend Indicators:**
- `↑ GETTING CLOSER` - RSSI improving by >2 dBm (move in current direction)
- `↓ Getting farther` - RSSI decreasing by >2 dBm (reverse direction)
- `→ Stable` - RSSI relatively constant (maintain position or search pattern)

**Implementation Details:**
- RadioTap header parsing for RSSI extraction
- IEEE 802.11 beacon frame parsing
- Source MAC address decoding for survivor ID
- Magic marker verification ("RESCUE")
- Multi-threaded: Sniffer thread + GUI thread
- Thread-safe survivor tracking with locks
- Rolling RSSI history (last 10 values)

---

### 4. secretKey.py

Implements RSSI-based symmetric key exchange using physical layer properties for cryptographic key generation.

**Idea:**
Two devices in close proximity exchange frames and measure RSSI (Received Signal Strength Indicator). Due to channel reciprocity, both devices should get similar RSSI values. By quantizing these measurements, they can independently generate matching cryptographic keys without transmitting the key itself.

**Usage:**
```bash
# Device 1
sudo python3 secretKey.py

# Device 2 (on another machine, same channel)
sudo python3 secretKey.py
```

**Protocol Phases:**

#### Phase 1: Role Determination
```
- Random delay (0-3 seconds) to avoid collisions
- Listen for 5 seconds for "READY" beacon
- If heard: Become RESPONDER, send ACK
- If not heard: Become INITIATOR, broadcast READY, wait for ACK
- Handle conflicts if both devices try to be initiator at the same time
```

#### Phase 2: Frame Exchange
```
Initiator → Responder: NUM_FRAMES data frames (300 by default)
Responder → Initiator: Immediate reply for each frame
Both devices: Record RSSI for each frame exchange
```

#### Phase 3: Key Bit Generation
```
1. Normalize RSSI measurements: z-score = (x - μ) / σ
2. For each frame:
   - If |z-score| > threshold: Generate bit
     * z-score > 0: bit = 1
     * z-score < 0: bit = 0
   - If |z-score| ≤ threshold: Discard (unreliable)
3. Result: Array of bits with indices
```

#### Phase 4: Index Reconciliation
```
Initiator → Responder: Send valid bit indices
Responder → Initiator: Send common indices (intersection)
Both: Build final key using only common indices
```

#### Phase 5: Verification
```
Initiator → Responder: Send SHA256(key) commitment
Responder: Compare with own SHA256(key)
Responder → Initiator: Send MATCH or MISMATCH result
Both: Display success/failure
```

**Configuration Parameters:**
```python
INTERFACE = "wlan0"       # Wi-Fi interface name
CHANNEL = 6               # Wi-Fi channel (1-11 for 2.4GHz)
NUM_FRAMES = 300          # Number of frame exchanges
TIMEOUT_ROLE = 5.0        # Role determination timeout (seconds)
TIMEOUT_FRAME = 0.15      # Per-frame reply timeout (seconds)
Z_THRESHOLD = 0.5         # Z-score threshold for key generation
```

**Frame Types:**
```python
FRAME_READY     # "KEY_EXCHANGE_READY_V1"    - Initiator beacon
FRAME_ACK       # "KEY_EXCHANGE_ACK_V1"      - Responder acknowledgment
FRAME_DATA      # "KEY_DATA_"                - RSSI measurement frame
FRAME_INDICES   # "KEY_INDICES_"             - Bit index exchange
FRAME_COMMIT    # "KEY_COMMIT_"              - Key hash commitment
FRAME_RESULT    # "KEY_RESULT_"              - Verification result
```

**Output Example:**
```
Wi-Fi RSSI-Based Key Exchange
[*] Setting up monitor mode...
[*] Interface: wlan0, Channel: 6
[+] Monitor mode enabled on wlan0 channel 6
[*] My MAC: 02:42:ac:11:00:02

[*] Phase 1: Determining role...
[*] Waiting 1.47s before role determination...
[*] Listening for 5.0s to detect initiator...
[+] Role: INITIATOR (no other device detected)
[*] Broadcasting READY frames and waiting for responder...
[+] ACK received from responder at 02:42:ac:11:00:03

[*] Phase 2: Exchanging frames (300 total)...
[*] Sending frames and measuring RSSI...
Frames exchanged: 50/300
Frames exchanged: 100/300
...
[+] Frame exchange complete!
[+] Successfully exchanged: 298/300 frames

[*] Phase 3: Generating key bits from RSSI...
[+] RSSI stats - Mean: -45.2 dBm, StdDev: 3.8 dBm
[+] Generated 156 key bits from 298 measurements

[*] Phase 4: Exchanging indices...
[*] Sending my indices to responder...
[*] Waiting for common indices from responder...
[+] My indices: 156
[+] Their indices: 152
[+] Common indices: 148

[*] Phase 5: Verifying key match...
[*] My key hash: 7f3a2e9b4c6d8a1f...
[*] Sending commitment to responder...
[*] Waiting for verification result...

============================================================
[+] SUCCESS! Keys match!
[+] Shared key: 11010010111001...
[+] Key length: 148 bits
[+] Key hash: 7f3a2e9b4c6d8a1f2b5e8c9a4d7f1e3c...
============================================================
```

---

## Technical Details

### RadioTap Header
All frames include RadioTap header for monitor mode:
- Version, padding, length, present flags
- Optional fields: RSSI, channel, rate, antenna, etc.

### IEEE 802.11 Frame Format
```
Management Frame (Type 0):
- Beacon (Subtype 8)
- Probe Request (Subtype 4)
- Probe Response (Subtype 5)

Data Frame (Type 2):
- Used by secretKey.py for custom exchanges
- LLC/SNAP encapsulation for payload
```

### RSSI Measurement
- Measured in dBm (decibel-milliwatts)
- Typical range: -30 dBm (very strong) to -100 dBm (very weak)
- Free space path loss: RSSI decreases ~6 dB per doubling of distance
- Affected by: obstacles, interference, antenna orientation

### Z-Score Quantization
```python
z = (x - μ) / σ  # Standardization

If |z| > threshold:
    bit = 1 if z > 0 else 0
Else:
    Discard (too close to mean)
```