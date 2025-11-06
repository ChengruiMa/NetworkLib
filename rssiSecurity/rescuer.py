#!/usr/bin/env python3
"""
Rescuer Detection Program
Detects survivor beacons and displays RSSI to guide rescue operations
Uses ncurses for real-time display
"""

import socket
import struct
import sys
import time
import curses
import threading
import subprocess
from collections import defaultdict
from datetime import datetime

class SurvivorTracker:
    def __init__(self):
        self.survivors = {}  # survivor_id -> {rssi, last_seen, history}
        self.lock = threading.Lock()
        self.running = True
    
    def update_survivor(self, survivor_id, rssi):
        """Update survivor information with new RSSI reading"""
        with self.lock:
            current_time = time.time()
            
            if survivor_id not in self.survivors:
                self.survivors[survivor_id] = {
                    'rssi': rssi,
                    'last_seen': current_time,
                    'history': [rssi],
                    'first_seen': current_time,
                    'packet_count': 1
                }
            else:
                self.survivors[survivor_id]['rssi'] = rssi
                self.survivors[survivor_id]['last_seen'] = current_time
                self.survivors[survivor_id]['packet_count'] += 1
                
                # Keep history of last 10 RSSI values
                history = self.survivors[survivor_id]['history']
                history.append(rssi)
                if len(history) > 10:
                    history.pop(0)
    
    def get_survivors(self):
        """Get current survivor data"""
        with self.lock:
            return dict(self.survivors)
    
    def stop(self):
        """Stop tracking"""
        self.running = False

def set_monitor_mode(interface, channel):
    """Call the monitor mode script to configure the interface"""
    print(f"Setting {interface} to monitor mode on channel {channel}...")
    result = subprocess.run(['./set_monitor_mode.sh', interface, str(channel)], 
                          capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(f"Error setting monitor mode: {result.stderr}")
        sys.exit(1)
    time.sleep(2)

def parse_radiotap_header(packet):
    """
    Parse RadioTap header to extract RSSI (antenna signal)
    Returns: (header_length, rssi)
    """
    if len(packet) < 8:
        return None, None
    
    # RadioTap header structure
    version, pad, length, present = struct.unpack('<BBHI', packet[:8])
    
    if length > len(packet):
        return None, None
    
    rssi = None
    offset = 8
    
    # Parse present flags to find antenna signal
    if present & (1 << 5):  
        # Skip other fields based on present flags
        if present & (1 << 0):  
            offset += 8
        if present & (1 << 1):  
            offset += 1
        if present & (1 << 2): 
            offset += 1
        if present & (1 << 3):  
            offset += 4
        if present & (1 << 4): 
            offset += 2
        
        # Antenna signal (dBm)
        if offset < length:
            rssi = struct.unpack('b', packet[offset:offset+1])[0]
    
    return length, rssi

def parse_beacon_frame(packet, radiotap_len):
    """
    Parse the beacon frame to extract survivor ID
    Returns: survivor_id or None
    """
    if radiotap_len is None or len(packet) < radiotap_len + 24:
        return None
    
    # Skip RadioTap header
    frame = packet[radiotap_len:]
    
    if len(frame) < 2:
        return None
    
    frame_control = struct.unpack('<H', frame[0:2])[0]
    frame_type = (frame_control >> 2) & 0x03
    frame_subtype = (frame_control >> 4) & 0x0F
    
    # Check if it's a beacon frame 
    if frame_type != 0 or frame_subtype != 8:
        return None
    
    # Extract source address 
    if len(frame) < 16:
        return None
    
    src_addr = frame[10:16]
    
    if src_addr[0] != 0x02 or src_addr[1] != 0x00:
        return None
    
    # Extract survivor ID 
    survivor_id = (src_addr[4] << 8) | src_addr[5]
    
    if len(frame) < 40:
        return None
    
    body_start = 36
    body = frame[body_start:]
    
    # Look for our magic marker "RESCUE"
    if b'RESCUE' in body:
        return survivor_id
    
    return None

def sniff_packets(interface, tracker):
    """Sniff packets on the interface and track survivors"""
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        sock.bind((interface, 0))
        sock.settimeout(1.0)
    except Exception as e:
        print(f"Error creating socket: {e}")
        return
    
    while tracker.running:
        try:
            packet, addr = sock.recvfrom(4096)
            
            # Parse RadioTap header
            radiotap_len, rssi = parse_radiotap_header(packet)
            
            if rssi is None:
                continue
            
            # Parse beacon frame
            survivor_id = parse_beacon_frame(packet, radiotap_len)
            
            if survivor_id is not None:
                tracker.update_survivor(survivor_id, rssi)
        
        except socket.timeout:
            continue
        except Exception as e:
            if tracker.running:
                pass  
    
    sock.close()

def get_signal_strength_bar(rssi):
    """Convert RSSI to a visual signal strength bar"""
    if rssi >= -50:
        return "▮▮▮▮▮ Excellent"
    elif rssi >= -60:
        return "▮▮▮▮▯ Very Good"
    elif rssi >= -70:
        return "▮▮▮▯▯ Good"
    elif rssi >= -80:
        return "▮▮▯▯▯ Fair"
    elif rssi >= -90:
        return "▮▯▯▯▯ Weak"
    else:
        return "▯▯▯▯▯ Very Weak"

def get_direction_indicator(history):
    """Determine if signal is getting stronger or weaker"""
    if len(history) < 3:
        return "→ Stable"
    
    # Compare recent average to older average
    recent = sum(history[-3:]) / 3
    older = sum(history[:3]) / 3
    
    diff = recent - older
    
    if diff > 2:
        return "↑ GETTING CLOSER"
    elif diff < -2:
        return "↓ Getting farther"
    else:
        return "→ Stable"

def display_gui(stdscr, tracker):
    """Display the ncurses GUI"""
    curses.curs_set(0)  
    stdscr.nodelay(1)   
    stdscr.timeout(100) # Refresh every 100ms
    
    # Colors for different signal strengths
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK) 
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)  
    curses.init_pair(4, curses.COLOR_CYAN, curses.COLOR_BLACK)   
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)  
    
    try:
        while tracker.running:
            stdscr.clear()
            height, width = stdscr.getmaxyx()
            
            # Header
            title = "SEARCH AND RESCUE - SURVIVOR DETECTOR"
            stdscr.addstr(0, (width - len(title)) // 2, title, 
                         curses.color_pair(4) | curses.A_BOLD)
            
            stdscr.addstr(1, 0, "=" * width)
            
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            stdscr.addstr(2, 2, f"Current Time: {current_time}")
            
            survivors = tracker.get_survivors()
            
            if not survivors:
                stdscr.addstr(4, 2, "No survivors detected yet...", 
                             curses.color_pair(2))
                stdscr.addstr(5, 2, "Scanning for beacon frames...", 
                             curses.color_pair(5))
            else:
                stdscr.addstr(4, 2, f"Survivors Detected: {len(survivors)}", 
                             curses.color_pair(1) | curses.A_BOLD)
                
                # Display each survivor
                row = 6
                for survivor_id, data in sorted(survivors.items()):
                    if row >= height - 3:
                        break
                    
                    rssi = data['rssi']
                    last_seen = data['last_seen']
                    history = data['history']
                    packet_count = data['packet_count']
                    
                    time_diff = time.time() - last_seen
                    
                    # Determine color based on RSSI
                    if rssi >= -60:
                        color = curses.color_pair(1)  
                    elif rssi >= -80:
                        color = curses.color_pair(2)  
                    else:
                        color = curses.color_pair(3)  
                    
                    # Display survivor info
                    stdscr.addstr(row, 2, "─" * (width - 4))
                    row += 1
                    
                    stdscr.addstr(row, 2, f"Survivor ID: {survivor_id:04d}", 
                                 curses.A_BOLD)
                    row += 1
                    
                    stdscr.addstr(row, 4, f"RSSI: {rssi:4d} dBm  ", color | curses.A_BOLD)
                    stdscr.addstr(row, 25, get_signal_strength_bar(rssi), color)
                    row += 1
                    
                    direction = get_direction_indicator(history)
                    if "CLOSER" in direction:
                        dir_color = curses.color_pair(1) | curses.A_BOLD
                    elif "farther" in direction:
                        dir_color = curses.color_pair(3)
                    else:
                        dir_color = curses.color_pair(5)
                    
                    stdscr.addstr(row, 4, f"Trend: {direction}", dir_color)
                    row += 1
                    
                    stdscr.addstr(row, 4, f"Last Seen: {time_diff:.1f}s ago")
                    stdscr.addstr(row, 30, f"Packets: {packet_count}")
                    row += 2
            
            # Instructions
            stdscr.addstr(height - 2, 0, "─" * width)
            stdscr.addstr(height - 1, 2, "Press 'q' to quit | Move toward increasing RSSI to find survivors")
            
            stdscr.refresh()
            
            # Check for quit
            key = stdscr.getch()
            if key == ord('q') or key == ord('Q'):
                tracker.stop()
                break
    
    except KeyboardInterrupt:
        tracker.stop()

def main():
    if len(sys.argv) != 3:
        print("Usage: sudo python3 rescuer.py <interface> <channel>")
        print("Example: sudo python3 rescuer.py wlan0 6")
        sys.exit(1)
    
    interface = sys.argv[1]
    channel = int(sys.argv[2])
    
    print("=" * 60)
    print("SEARCH AND RESCUE - RESCUER PROGRAM")
    print("=" * 60)
    print(f"Interface: {interface}")
    print(f"Channel: {channel}")
    print("=" * 60)
    print()
    
    # Set monitor mode
    set_monitor_mode(interface, channel)
    
    # Create tracker
    tracker = SurvivorTracker()
    
    # Start sniffing thread
    sniffer_thread = threading.Thread(target=sniff_packets, args=(interface, tracker))
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    print("Starting survivor detection...")
    print("Launching GUI in 2 seconds...\n")
    time.sleep(2)
    
    # Start GUI
    try:
        curses.wrapper(display_gui, tracker)
    except KeyboardInterrupt:
        pass
    finally:
        tracker.stop()
        sniffer_thread.join(timeout=2)
        print("\nRescuer program terminated.")

if __name__ == "__main__":
    main()