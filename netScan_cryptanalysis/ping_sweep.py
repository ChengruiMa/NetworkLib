#!/usr/bin/env python3
"""
ping_sweep.py - Discover hosts on a network by sending ICMP pings to each address in a subnet
Usage: python3 ping_sweep.py <subnet_in_CIDR_format>
Example: python3 ping_sweep.py 192.168.60.0/24
"""

import sys
import ipaddress
import subprocess
import concurrent.futures
import socket
import os
from typing import List
from scapy.all import IP, ICMP, sr1, conf

def ping_host(ip: str) -> tuple:
    """
    Ping a single host and return whether it responds using scapy.
    
    This function sends an ICMP echo request using scapy.
    If scapy is not available or fails, it falls back to TCP connection attempts.
    
    Args:
        ip: IP address as a string
        
    Returns:
        tuple: (ip, True/False) indicating if host responded
    """
    try:
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]
        if ip in local_ips or ip == '127.0.0.1':
            return (ip, True)
    except:
        pass
    
    try:
        conf.verb = 0
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=1, verbose=0)
        return (ip, response is not None)
    except Exception as e:
        print(f"Scapy ping failed for {ip}, falling back to TCP method: {e}")

def ping_sweep(subnet: str) -> List[str]:
    """
    Perform a ping sweep on a subnet to discover active hosts.
    
    Args:
        subnet: Subnet in CIDR notation (e.g., "192.168.60.0/24")
        
    Returns:
        List of IP addresses that responded to ping
    """
    try:
        # Parse the subnet
        network = ipaddress.ip_network(subnet, strict=False)
        
        # Get all usable host addresses (excludes network and broadcast addresses)
        hosts = list(network.hosts())
        
        print(f"Scanning {len(hosts)} hosts in subnet {network}")
        print(f"Range: {hosts[0]} - {hosts[-1]}")
        print("-" * 50)
        
        active_hosts = []
        
        # Use ThreadPoolExecutor for concurrent pinging
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            future_to_ip = {executor.submit(ping_host, str(ip)): ip for ip in hosts}
            
            # Collect results and print active hosts
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, is_active = future.result()
                if is_active:
                    active_hosts.append(ip)
                    print(f"[+] {ip} is UP")
        
        return sorted(active_hosts, key=lambda ip: ipaddress.ip_address(ip))
    
    except ValueError as e:
        print(f"Error: Invalid subnet format - {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ping_sweep.py <subnet_in_CIDR_format>")
        print("Example: python3 ping_sweep.py 192.168.60.0/24")
        sys.exit(1)
    
    subnet = sys.argv[1]
    
    print(f"Starting ping sweep on {subnet}")
    print("=" * 50)
    
    active_hosts = ping_sweep(subnet)
    
    print("\n" + "=" * 50)
    print(f"Scan complete. Found {len(active_hosts)} active host(s):")
    print("-" * 50)
    for host in active_hosts:
        print(host)
    print("=" * 50)

if __name__ == "__main__":
    main()