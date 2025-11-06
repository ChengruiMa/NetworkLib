#!/usr/bin/env python3
"""
Tester for network layers and functions library
Tests ICMP ping, DNS query, and TCP HTTP GET
Run with sudo privileges: sudo python3 tester.py
Written with assistance from ChatGPT and Claude on 
hexadecimals, library usage, fonts and debugging.
"""

import socket
import subprocess
import time
import random
from layers import *
from network_functions import *


def get_local_ip():
    """Get the local IP address"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect to external address 
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    return local_ip


def get_local_mac(interface='eth0'):
    """Get local MAC address for given interface"""
    try:
        with open(f'/sys/class/net/{interface}/address', 'r') as f:
            return f.read().strip()
    except:
        # Try common interface names
        for iface in ['eth0', 'ens33', 'ens160', 'enp0s3']:
            try:
                with open(f'/sys/class/net/{iface}/address', 'r') as f:
                    return f.read().strip()
            except:
                continue
    return "00:00:00:00:00:00"


def get_gateway_mac():
    """Get MAC address of default gateway using arp"""
    try:
        # First, get the default gateway IP
        route_result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                     capture_output=True, text=True)
        gateway_ip = None
        for word in route_result.stdout.split():
            if '.' in word and word.count('.') == 3:
                gateway_ip = word
                break
        
        if gateway_ip:
            # Run arp command to get gateway MAC
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                if gateway_ip in line:
                    parts = line.split()
                    # MAC address is usually the 3rd column (index 2)
                    if len(parts) >= 3:
                        mac = parts[2]
                        # Validate MAC address format (xx:xx:xx:xx:xx:xx)
                        if ':' in mac and len(mac.replace(':', '')) == 12:
                            return mac
        
        # Fallback: get first valid entry that's not incomplete
        result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        for line in lines[1:]:  
            parts = line.split()
            if len(parts) >= 3:
                mac = parts[2]
                if ':' in mac and mac != '<incomplete>' and len(mac.replace(':', '')) == 12:
                    return mac
    except Exception as e:
        print(f"Warning: Could not get gateway MAC: {e}")
    return "ff:ff:ff:ff:ff:ff"


def test_icmp_ping():
    """Test 1: ICMP Ping using send, sendp, and sr"""
    print("=" * 70)
    print("TEST 1: ICMP PING")
    print("=" * 70)
    
    # Get network info
    my_ip = get_local_ip()
    my_mac = get_local_mac()
    gateway_mac = get_gateway_mac()
    target_ip = "8.8.8.8"  # Google DNS
    
    print(f"\nNetwork Configuration:")
    print(f"  Local IP: {my_ip}")
    print(f"  Local MAC: {my_mac}")
    print(f"  Gateway MAC: {gateway_mac}")
    print(f"  Target IP: {target_ip}")
    
    # Create ICMP ping packet
    print(f"\n--- Test 1a: send() at Layer 3 ---")
    pkt = IP(src_ip=my_ip, dst_ip=target_ip) / ICMP(id=1234, seq=1, type=8)
    print("Packet structure:")
    pkt.show()
    print(f"Packet bytes: {pkt.build().hex()}")
    print(f"Packet size: {len(pkt.build())} bytes")
    print("\nSending packet...")
    send(pkt)
    print("✓ Packet sent via send() - Check Wireshark for transmission and reply. Sleeping 10 seconds to allow time for capture.")
    time.sleep(10)
    
    # Test sendp at layer 2
    print(f"\n--- Test 1b: sendp() at Layer 2 ---")
    pkt2 = Ether(src_mac=my_mac, dst_mac=gateway_mac) / IP(src_ip=my_ip, dst_ip=target_ip) / ICMP(id=1235, seq=2, type=8)
    print("Packet structure:")
    pkt2.show()
    print(f"\nPacket will be {len(pkt2.build())} bytes")
    print("\nSending packet...")
    try:
        # Try to determine interface name
        interface = 'eth0'
        for iface in ['eth0', 'ens33', 'ens160', 'enp0s3']:
            try:
                with open(f'/sys/class/net/{iface}/address', 'r'):
                    interface = iface
                    break
            except:
                continue
        print(f"Using interface: {interface}")
        sendp(pkt2, interface)
        print("✓ Packet sent via sendp() - Check Wireshark for transmission and reply. Sleeping 10 seconds to allow time for capture.")
    except Exception as e:
        print(f"✗ Error sending via sendp: {e}")
        import traceback
        traceback.print_exc()
    time.sleep(10)
    
    # Test sr - send and receive
    print(f"\n--- Test 1c: sr() - Send and Receive ---")
    pkt3 = Ether(src_mac=my_mac, dst_mac=gateway_mac) / IP(src_ip=my_ip, dst_ip=target_ip) / ICMP(id=1236, seq=3, type=8)
    print("Packet structure:")
    pkt3.show()
    print("\nSending packet and waiting for reply...")
    reply = sr(pkt3, timeout=5)
    
    if reply:
        print("\n✓ Reply received:")
        reply.show()
    else:
        print("✗ No reply received (timeout)")
    
    print("\n" + "=" * 70)


def test_dns_query():
    """Test 2: DNS Query for A record"""
    print("=" * 70)
    print("TEST 2: DNS QUERY")
    print("=" * 70)
    
    # Get network info
    my_ip = get_local_ip()
    my_mac = get_local_mac()
    gateway_mac = get_gateway_mac()
    dns_server = "8.8.8.8"
    domain = "vibrantcloud.org"
    
    print(f"\nQuerying DNS for: {domain}")
    print(f"DNS Server: {dns_server}")
    
    # Create DNS query packet
    dns_query = DNS(qname=domain, qtype=1, qclass=1)
    udp_layer = UDP(sport=random.randint(49152, 65535), dport=53)
    ip_layer = IP(src_ip=my_ip, dst_ip=dns_server)
    eth_layer = Ether(src_mac=my_mac, dst_mac=gateway_mac)
    
    pkt = eth_layer / ip_layer / udp_layer / dns_query
    
    print("\nPacket structure:")
    pkt.show()
    
    print("\nSending DNS query...")
    reply = sr(pkt, timeout=5)
    
    if reply:
        print("\n✓ DNS Reply received:")
        reply.show()
        
        # Extract IP address from DNS reply
        dns_reply = reply.get_layer('DNS')
        if dns_reply and hasattr(dns_reply, 'addr'):
            print(f"\n✓ Resolved IP address: {dns_reply.addr}")
            print("=" * 70)
            return dns_reply.addr
        else:
            print("\n✗ Could not extract IP address from reply")
    else:
        print("\n✗ No DNS reply received")
    
    print("=" * 70)
    return None


def test_tcp_http_get(target_ip=None):
    """Test 3: TCP HTTP GET with three-way handshake"""
    print("=" * 70)
    print("TEST 3: TCP HTTP GET")
    print("=" * 70)
    
    # Get network info
    my_ip = get_local_ip()
    my_mac = get_local_mac()
    gateway_mac = get_gateway_mac()
    
    # Use provided IP or resolve vibrantcloud.org
    if target_ip is None:
        print("\nResolving vibrantcloud.org...")
        target_ip = test_dns_query()
        if target_ip is None:
            print("✗ Failed to resolve target IP")
            return
    
    target_port = 80
    source_port = random.randint(49152, 65535)
    
    print(f"\nTCP Connection Parameters:")
    print(f"  Source: {my_ip}:{source_port}")
    print(f"  Target: {target_ip}:{target_port}")
    
    # Add iptables rule to prevent RST
    print("\n--- Setting up firewall rule to prevent RST ---")
    try:
        command = ['sudo', 'iptables', '-A', 'OUTPUT', '-p', 'tcp', '-m', 'tcp', 
                   '--tcp-flags', 'RST', 'RST', '-j', 'DROP']
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("✓ Firewall rule added")
    except Exception as e:
        print(f"✗ Failed to add firewall rule: {e}")
        return
    
    try:
        # Step 1: Send SYN
        print("\n--- Step 1: Sending SYN ---")
        initial_seq = random.randint(0, 4294967295)
        syn_flags = 0x002  # SYN flag
        
        syn_pkt = Ether(src_mac=my_mac, dst_mac=gateway_mac) / \
                  IP(src_ip=my_ip, dst_ip=target_ip) / \
                  TCP(sport=source_port, dport=target_port, seq=initial_seq, 
                      ack=0, flags=syn_flags, window=65535)
        
        print("SYN packet:")
        syn_pkt.show()
        
        syn_ack_reply = sr(syn_pkt, timeout=5)
        
        if not syn_ack_reply:
            print("✗ No SYN-ACK received")
            return
        
        print("\n✓ SYN-ACK received:")
        syn_ack_reply.show()
        
        # Extract TCP layer from reply
        tcp_reply = syn_ack_reply.get_layer('TCP')
        if not tcp_reply:
            print("✗ No TCP layer in reply")
            return
        
        server_seq = tcp_reply.seq
        server_ack = tcp_reply.ack
        
        print(f"\nServer SEQ: {server_seq}")
        print(f"Server ACK: {server_ack}")
        
        # Step 2: Send ACK
        print("\n--- Step 2: Sending ACK ---")
        ack_flags = 0x010  # ACK flag
        
        ack_pkt = Ether(src_mac=my_mac, dst_mac=gateway_mac) / \
                  IP(src_ip=my_ip, dst_ip=target_ip) / \
                  TCP(sport=source_port, dport=target_port, seq=server_ack, 
                      ack=server_seq + 1, flags=ack_flags, window=65535)
        
        send(ack_pkt)
        print("✓ ACK sent - Connection established")
        time.sleep(0.5)
        
        # Step 3: Send HTTP GET request
        print("\n--- Step 3: Sending HTTP GET ---")
        http_request = b"GET /index.html HTTP/1.1\r\nHost: vibrantcloud.org\r\nConnection: close\r\n\r\n"
        
        psh_ack_flags = 0x018  # PSH + ACK flags
        
        http_pkt = Ether(src_mac=my_mac, dst_mac=gateway_mac) / \
                   IP(src_ip=my_ip, dst_ip=target_ip) / \
                   TCP(sport=source_port, dport=target_port, seq=server_ack, 
                       ack=server_seq + 1, flags=psh_ack_flags, window=65535, 
                       data=http_request)
        
        print("HTTP GET packet:")
        http_pkt.show()
        
        # Send HTTP request
        send(http_pkt)
        print("✓ HTTP GET sent")
        
        # Step 4: Receive HTTP response
        print("\n--- Step 4: Receiving HTTP Response ---")
        print("Waiting for response packets...")
        
        http_response = b""
        expected_seq = server_seq + 1
        
        for i in range(20):  # Try to receive multiple packets
            try:
                response_pkt = sniff(timeout=2)
                if response_pkt:
                    ip_layer = response_pkt.get_layer('IP')
                    tcp_layer = response_pkt.get_layer('TCP')
                    
                    # Filter for packets from our connection
                    if (tcp_layer and ip_layer and 
                        tcp_layer.sport == target_port and 
                        tcp_layer.dport == source_port and
                        ip_layer.src_ip == target_ip):
                        
                        # Send ACK for received data
                        if hasattr(tcp_layer, 'message') and tcp_layer.message:
                            data_len = len(tcp_layer.message)
                            http_response += tcp_layer.message
                            print(f"✓ Received packet ({len(http_response)} bytes total)")
                            
                            # Send ACK
                            expected_seq = tcp_layer.seq + data_len
                            ack_pkt = Ether(src_mac=my_mac, dst_mac=gateway_mac) / \
                                     IP(src_ip=my_ip, dst_ip=target_ip) / \
                                     TCP(sport=source_port, dport=target_port,
                                         seq=tcp_layer.ack, ack=expected_seq,
                                         flags=0x010, window=65535)
                            send(ack_pkt)
                        
                        # Check for FIN flag (connection closing)
                        if tcp_layer.flags & 0x001:
                            print("✓ FIN received - sending FIN-ACK")
                            # Send FIN-ACK
                            fin_ack_pkt = Ether(src_mac=my_mac, dst_mac=gateway_mac) / \
                                         IP(src_ip=my_ip, dst_ip=target_ip) / \
                                         TCP(sport=source_port, dport=target_port,
                                             seq=tcp_layer.ack, ack=tcp_layer.seq + 1,
                                             flags=0x011, window=65535)  # FIN + ACK
                            send(fin_ack_pkt)
                            break
            except Exception as e:
                print(f"Error receiving packet: {e}")
                break
        
        if http_response:
            print(f"\n✓ Total HTTP response received: {len(http_response)} bytes")
            print("\n" + "=" * 70)
            print("HTTP RESPONSE:")
            print("=" * 70)
            try:
                print(http_response.decode('utf-8', errors='ignore'))
            except:
                print(http_response)
            print("=" * 70)
        else:
            print("\n✗ No HTTP response received")
    
    finally:
        # Remove iptables rule
        print("\n--- Removing firewall rule ---")
        try:
            command = ['sudo', 'iptables', '-D', 'OUTPUT', '-p', 'tcp', '-m', 'tcp',
                       '--tcp-flags', 'RST', 'RST', '-j', 'DROP']
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            print("✓ Firewall rule removed")
        except Exception as e:
            print(f"⚠ Failed to remove firewall rule: {e}")
            print("You may need to manually remove it with:")
            print("sudo iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP")


def main():
    """Run all tests"""
    print("\n" + "=" * 70)
    print("NETWORK PACKET LIBRARY TESTER")
    print("=" * 70)
    print("\nThis script will test:")
    print("1. ICMP Ping (send, sendp, sr)")
    print("2. DNS Query for A record")
    print("3. TCP HTTP GET with three-way handshake")
    print("Make sure to run with sudo privileges")
    print("=" * 70)
    
    input("\nPress Enter to start tests...")
    
    # Test 1: ICMP Ping
    try:
        test_icmp_ping()
    except Exception as e:
        print(f"\n✗ ICMP test failed: {e}")
    
    print("\n")
    input("Press Enter to continue to DNS test...")
    
    # Test 2: DNS Query
    try:
        resolved_ip = test_dns_query()
    except Exception as e:
        print(f"\n✗ DNS test failed: {e}")
        resolved_ip = None
    
    print("\n")
    input("Press Enter to continue to TCP HTTP GET test...")
    
    # Test 3: TCP HTTP GET
    try:
        test_tcp_http_get(resolved_ip)
    except Exception as e:
        print(f"\n✗ TCP HTTP GET test failed: {e}")
    
    print("\n" + "=" * 70)
    print("ALL TESTS COMPLETED")
    print("=" * 70)
    print("If firewall rule wasn't removed, run:")
    print("sudo iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP")
    print("=" * 70)


if __name__ == "__main__":
    # Check if running as root
    import os
    if os.geteuid() != 0:
        print("ERROR: This script must be run with sudo privileges")
        print("Usage: sudo python3 tester.py")
        exit(1)
    
    main()