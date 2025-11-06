#!/usr/bin/env python3
"""
Survivor Beacon Program
Transmits custom beacon frames with unique survivor ID for rescue localization
"""

import socket
import struct
import time
import sys
import random
import subprocess

def set_monitor_mode(interface, channel):
    """Call the monitor mode script to configure the interface"""
    print(f"Setting {interface} to monitor mode on channel {channel}...")
    result = subprocess.run(['./set_monitor_mode.sh', interface, str(channel)], 
                          capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error setting monitor mode: {result.stderr}")
        sys.exit(1)
    time.sleep(2)  # Give the interface time to stabilize

def create_radiotap_header():
    """
    Create a RadioTap header for raw packet injection
    RadioTap header format (minimal):
    - version (1 byte): 0
    - pad (1 byte): 0
    - length (2 bytes): 8 (header length)
    - present flags (4 bytes): 0 (no additional fields)
    """
    version = 0
    pad = 0
    length = 8
    present = 0
    
    return struct.pack('<BBHI', version, pad, length, present)

def create_beacon_frame(survivor_id, sequence_num):
    """
    Create a custom beacon frame
    Uses IEEE 802.11 management frame format with custom beacon subtype
    
    Frame structure:
    - Frame Control (2 bytes): Type=0 (Management), Subtype=8 (Beacon)
    - Duration (2 bytes): 0
    - Destination Address (6 bytes): Broadcast (FF:FF:FF:FF:FF:FF)
    - Source Address (6 bytes): Custom MAC based on survivor_id
    - BSSID (6 bytes): Same as source
    - Sequence Control (2 bytes): Fragment=0, Sequence number
    - Beacon Payload: Custom data with survivor ID and timestamp
    """
    
    # Frame Control: Type=Management (00), Subtype=Beacon (1000)
    # 0x0080 = 0b0000000010000000 (little endian)
    frame_control = struct.pack('<H', 0x0080)
    
    # Duration
    duration = struct.pack('<H', 0)
    
    # Destination: Broadcast
    dest_addr = b'\xff\xff\xff\xff\xff\xff'
    
    # Source Address: Custom MAC based on survivor_id
    # Format: 02:00:00:00:XX:YY where XX:YY represents survivor_id
    src_addr = struct.pack('BBBBBB', 0x02, 0x00, 0x00, 0x00, 
                          (survivor_id >> 8) & 0xFF, survivor_id & 0xFF)
    
    # BSSID: Same as source
    bssid = src_addr
    
    # Sequence Control
    seq_ctrl = struct.pack('<H', (sequence_num << 4) & 0xFFF0)
    
    # Beacon payload - custom information element
    # Element ID (221 = vendor specific), Length, OUI, Custom data
    timestamp = int(time.time())
    
    # Create custom payload with survivor ID and timestamp
    payload = b'RESCUE'  # Magic marker
    payload += struct.pack('<HI', survivor_id, timestamp)
    payload += b' SOS - Need Help!'
    
    # Information Element: Vendor Specific (221)
    ie_id = 221
    ie_length = len(payload)
    ie_data = struct.pack('BB', ie_id, ie_length) + payload
    
    # Timestamp field (8 bytes) - required for beacon frames
    timestamp_field = struct.pack('<Q', timestamp * 1000000)  # Convert to microseconds
    
    # Beacon Interval (2 bytes) - 100 TUs (Time Units, 1 TU = 1024 μs)
    beacon_interval = struct.pack('<H', 100)
    
    # Capability Info (2 bytes)
    capability = struct.pack('<H', 0x0001)  # ESS capability
    
    # Assemble the complete frame
    beacon = (frame_control + duration + dest_addr + src_addr + bssid + 
             seq_ctrl + timestamp_field + beacon_interval + capability + ie_data)
    
    return beacon

def main():
    if len(sys.argv) != 3:
        print("Usage: sudo python3 survivor.py <interface> <channel>")
        print("Example: sudo python3 survivor.py wlan0 6")
        sys.exit(1)
    
    interface = sys.argv[1]
    channel = int(sys.argv[2])
    
    # Generate a unique survivor ID (1-9999)
    survivor_id = random.randint(1, 9999)
    
    print("=" * 60)
    print("SURVIVOR BEACON TRANSMITTER")
    print("=" * 60)
    print(f"Survivor ID: {survivor_id}")
    print(f"Interface: {interface}")
    print(f"Channel: {channel}")
    print("=" * 60)
    
    # Set monitor mode
    set_monitor_mode(interface, channel)
    
    # Create raw socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((interface, 0))
    except PermissionError:
        print("Error: This script must be run with sudo privileges")
        sys.exit(1)
    except OSError as e:
        print(f"Error creating socket: {e}")
        print("Make sure the interface exists and is in monitor mode")
        sys.exit(1)
    
    print("\nTransmitting beacon frames... Press Ctrl+C to stop")
    print(f"Rescuers should look for Survivor ID: {survivor_id}\n")
    
    sequence_num = 0
    packet_count = 0
    
    try:
        while True:
            # Create RadioTap header
            radiotap = create_radiotap_header()
            
            # Create beacon frame
            beacon = create_beacon_frame(survivor_id, sequence_num)
            
            # Combine and send
            packet = radiotap + beacon
            sock.send(packet)
            
            packet_count += 1
            sequence_num = (sequence_num + 1) % 4096
            
            if packet_count % 10 == 0:
                print(f"Beacons sent: {packet_count} (ID: {survivor_id}, Seq: {sequence_num})")
            
            # Transmit beacon every 100ms (10 times per second)
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print(f"\n\nStopping beacon transmission...")
        print(f"Total beacons sent: {packet_count}")
    except Exception as e:
        print(f"\nError during transmission: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()