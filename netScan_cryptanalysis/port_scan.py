#!/usr/bin/env python3
"""
port_scan.py - Discover open TCP ports on a host by sending SYN packets
Usage: python3 port_scan.py <ip_address> <port_range>
Example: python3 port_scan.py 192.168.60.5 1-1024,8080

Highest is only up to 4 so the smallest subnet mask would be:
192.168.60/29

This leaves 3 host bits 2^3 = 8 total addresses.  Since network and broadcast are reserved this leaves 6 available (2 bits would have been too few available)
"""

import sys
import socket
import concurrent.futures
from typing import List, Set
from scapy.all import IP, TCP, sr1, conf

def parse_port(port_spec: str) -> Set[int]:
    """
    Parse port string into a set of port numbers.
    
    Args:
        port_spec: Port specification (e.g., "1-1024,8080,9000-9010")
        
    Returns:
        Set of port numbers to scan
    """
    ports = set()
    
    # Split by comma to get individual port
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()
        
        # Range of ports
        if '-' in part:
            try:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError(f"Invalid port range: {part}")
                
                ports.update(range(start_port, end_port + 1))
            except ValueError as e:
                print(f"Error parsing port range '{part}': {e}")
                sys.exit(1)
        
        # Single port
        else:  
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port number must be between 1 and 65535")
                ports.add(port)
            except ValueError as e:
                print(f"Error parsing port '{part}': {e}")
                sys.exit(1)
    
    return ports

def scan_port(ip: str, port: int, timeout: float = 1.0) -> tuple:
    """
    Scan a single port on a host to check if it's open.
    This sends a TCP SYN packet and listens for SYN-ACK response.
    If we receive a SYN-ACK, the port is open.
    If we receive RST, the port is closed.
    
    Args:
        ip: IP address to scan
        port: Port number to scan
        timeout: Response timeout in seconds
    
    Returns:
        tuple: (port, is_open)
    """
    try:
        conf.verb = 0
        
        # Create a TCP SYN packet
        syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')
        
        # Send the packet and wait for a response
        response = sr1(syn_packet, timeout=timeout, verbose=0)
        
        # Check if we got a response
        if response is None:
            return (port, False)
        
        # Check if we got a SYN-ACK (flags=0x12)
        if response.haslayer(TCP):
            if response[TCP].flags == 0x12:  # SYN-ACK
                # Send RST to close the connection 
                rst_packet = IP(dst=ip) / TCP(dport=port, flags='R')
                sr1(rst_packet, timeout=0.5, verbose=0)
                return (port, True)
            elif response[TCP].flags == 0x14:  # RST-ACK
                # Port is closed
                return (port, False)
        
        return (port, False)
        
    except Exception:
        return (port, False)

def port_scan(ip: str, ports: Set[int]) -> List[int]:
    """
    Scan multiple ports on a host to find open ones.
    
    Args:
        ip: IP address to scan
        ports: Set of port numbers to scan
        
    Returns:
        List of open port numbers (sorted)
    """
    print(f"Scanning {len(ports)} port(s) on {ip}")
    print("-" * 50)
    
    open_ports = []
    
    # Use ThreadPoolExecutor for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in ports}
        
        # Collect results and print open ports
        completed = 0
        for future in concurrent.futures.as_completed(future_to_port):
            port, is_open = future.result()
            completed += 1
            
            if is_open:
                open_ports.append(port)
                print(f"[+] Port {port}/tcp is OPEN")
            
            # Show progress every 100 ports
            if completed % 100 == 0:
                print(f"Progress: {completed}/{len(ports)} ports scanned...")
    
    return sorted(open_ports)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 port_scan.py <ip_address> <port_range>")
        print("Example: python3 port_scan.py 192.168.60.5 1-1024,8080")
        print("\nPort range format:")
        print("  - Use dash (-) for ranges: 1-1024")
        print("  - Use comma (,) to separate: 1-1024,8080")
        print("  - Combine both: 1-100,200-300,8080")
        sys.exit(1)
    
    ip_address = sys.argv[1]
    port_spec = sys.argv[2]
    
    # Validate IP address
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        print(f"Error: Invalid IP address '{ip_address}'")
        sys.exit(1)
    
    # Parse port specification
    ports_to_scan = parse_port(port_spec)
    
    print(f"Starting port scan on {ip_address}")
    print(f"Ports to scan: {len(ports_to_scan)}")
    print("=" * 50)
    
    # Perform the scan
    open_ports = port_scan(ip_address, ports_to_scan)
    
    # Display results
    print("\n" + "=" * 50)
    print(f"Scan complete. Found {len(open_ports)} open port(s):")
    print("-" * 50)
    
    if open_ports:
        for port in open_ports:
            print(f"Port {port}/tcp")
    else:
        print("No open ports found.")
    
    print("=" * 50)

if __name__ == "__main__":
    main()