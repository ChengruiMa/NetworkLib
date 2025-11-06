#!/usr/bin/env python3
"""
Network function library for send, sendp, sr, and sniff
Written with assistance from ChatGPT and Claude on 
hexadecimals, bytes, library usage, and debugging.
"""

import socket
import time
from layers import *

def send(pkt):
    """
    Send packet at layer 3 (IP layer).
    If packet starts with Ether layer, extract the IP layer first.
    """
    # If packet starts with Ether, get the payload (should be IP)
    if isinstance(pkt, Ether):
        if pkt.payload is None:
            raise ValueError("No IP layer found in packet")
        pkt = pkt.payload
    
    if not isinstance(pkt, IP):
        raise ValueError("Packet must be IP layer or Ether/IP for send()")
    
    # Create raw socket for layer 3
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    
    try:
        # Build packet bytes starting from IP layer
        packet_bytes = pkt.build()
        
        # Send to destination IP
        dst_ip = pkt.dst_ip
        sock.sendto(packet_bytes, (dst_ip, 0))
        print(f"Sent {len(packet_bytes)} bytes to {dst_ip}")
    finally:
        sock.close()


def sendp(pkt, interface):
    """
    Send packet at layer 2 (Ethernet layer).
    Packet must start with Ether layer.
    """
    if not isinstance(pkt, Ether):
        raise ValueError("Packet must start with Ether layer for sendp")
    
    # Create raw socket for layer 2
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    
    try:
        # Bind to interface
        sock.bind((interface, 0))
        
        # Build packet bytes
        packet_bytes = pkt.build()
        
        # Send the packet
        sock.send(packet_bytes)
        print(f"Sent {len(packet_bytes)} bytes on interface {interface}")
    finally:
        sock.close()

def sr(pkt, timeout=5):
    """
    Send packet at layer 3 and receive reply at layer 2.
    Returns the received packet.
    """
    # Send the packet (will extract IP layer if needed)
    if isinstance(pkt, Ether):
        if pkt.payload is None:
            raise ValueError("No IP layer found in packet")
        ip_pkt = pkt.payload
    else:
        ip_pkt = pkt
    
    if not isinstance(ip_pkt, IP):
        raise ValueError("Packet must contain IP layer")
    
    # Remember what we're looking for
    src_ip = ip_pkt.src_ip
    dst_ip = ip_pkt.dst_ip
    
    print(f"Looking for replies from {dst_ip} to {src_ip}")
    
    # Send using layer 3
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    try:
        packet_bytes = ip_pkt.build()
        sock.sendto(packet_bytes, (ip_pkt.dst_ip, 0))
        print(f"Sent {len(packet_bytes)} bytes to {ip_pkt.dst_ip}")
    finally:
        sock.close()
    
    # Create receiving socket at layer 2
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    recv_sock.settimeout(timeout)
    
    try:
        # Receive replies - may need to filter through multiple packets
        start_time = time.time()
        packet_count = 0
        while time.time() - start_time < timeout:
            try:
                data, addr = recv_sock.recvfrom(65535)
                packet_count += 1
                
                # Build packet from received bytes
                reply_pkt = Ether(raw_bytes=data)
                
                # Check if this is a reply to our packet
                ip_layer = reply_pkt.get_layer('IP')
                if ip_layer:
                    proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(ip_layer.proto, str(ip_layer.proto))
                    print(f"Packet {packet_count}: {ip_layer.src_ip} -> {ip_layer.dst_ip}, proto={proto_name}")
                    
                    # Reply must come FROM dst_ip TO src_ip
                    if ip_layer.src_ip == dst_ip and ip_layer.dst_ip == src_ip:
                        print(f"Match found!")
                        return reply_pkt
            except socket.timeout:
                break
        
        print(f"Timeout: No matching reply received (saw {packet_count} packets)")
        return None
    finally:
        recv_sock.close()

def sniff(timeout=None):
    """
    Receive one packet at layer 2 and build packet from bytes.
    Returns the received packet.
    """
    # Create receiving socket at layer 2
    recv_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    
    if timeout:
        recv_sock.settimeout(timeout)
    
    try:
        # Receive packet
        data, addr = recv_sock.recvfrom(65535)
        
        # Build packet from received bytes
        pkt = Ether(raw_bytes=data)
        
        return pkt
    except socket.timeout:
        print("Timeout: No packet received")
        return None
    finally:
        recv_sock.close()