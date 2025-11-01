#!/usr/bin/env python3
from scapy.all import *

# Use Scapy to write your own ping tool. The program should take the targets IP address, or domain as a command line parameter
# and should repeatedly send requests once per second to the target. Use Scapy's sr1 command to both send a packet and receive a reply
# for one packet as shown

# Inputs: IP or domain name

#How to run: sudo python3 ping_scapy.py <host>
#Examples:
#Input: sudo python3 ping_scapy.py google.com
#Output: PING google.com (142.250.xxx.xxx): 56 
#Input: sudo python3 ping_scapy.py 8.8.8.8
#Ouptut: PING 8.8.8.8 (8.8.8.8): 56...

#Psuedo code:
#1. Parrse IP or domain from the command line
#2. If it is a domain, turn it to an IP with "socket.gethostbyname()"
#3. Build an ICMP packet in Scapy (ICMP = Internet Control Message Protocol)
#4. In a loop of (1Hz = 1 sec), send with sr1(.., timout=1) and time it
#5. Print output lines that mirro the system ping
#7 Track stacks (sent/received/avg RTT)
#7. Stop with Ctrl-C and print a summary

#Most comments written with help of GenAI

import sys, time, socket, signal
from scapy.all import IP, ICMP, sr1, conf

def resolve_input(input_str): #function definition for IP'ification
    try:
        socket.inet_aton(input_str) #raises an OS error if not valid IPv4 address
        return(input_str, input_str) # We have a valid IP address, now what about the domain name?
    except OSError:
        IP_addr = socket.gethostbyname(input_str) #performs a DNS lookup to return an IPv4 address
        return(input_str, IP_addr)

def main():

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <ip-or-domain>")
        sys.exit(1)

    input_str = sys.argv[1]
    domain_name, dst_ip = resolve_input(input_str)

    print(f"PING {domain_name} ({dst_ip}): 56 data bytes")

    count_sent = 0
    count_recv = 0
    rtts_ms = []

    # Optional: lower Scapy verbosity
    conf.verb = 0

    def handle_sigint(sig, frame): #Written with help from GenAI
        # Print summary on Ctrl-C
        loss = 100.0 * (count_sent - count_recv) / max(1, count_sent)
        avg = (sum(rtts_ms) / len(rtts_ms)) if rtts_ms else 0.0
        print("\n--- {} ping statistics ---".format(domain_name))
        print(f"{count_sent} packets transmitted, {count_recv} packets received, {loss:.1f}% packet loss")
        if rtts_ms:
            print(f"round-trip min/avg/max = {min(rtts_ms):.3f}/{avg:.3f}/{max(rtts_ms):.3f} ms")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    seq = 0
    while True:
        pkt = IP(dst=dst_ip)/ICMP(id=0x1234, seq=seq)  
        count_sent += 1

        t0 = time.monotonic_ns()
        reply = sr1(pkt, timeout=1)  # 1s timeout is typical
        t1 = time.monotonic_ns()

        if reply is None:
            print(f"No reply for icmp_seq {seq}")
        else:
            # Validate it's an ICMP Echo Reply (type 0)
            if reply.haslayer(ICMP) and reply[ICMP].type == 0:
                rtt_ms = (t1 - t0)/1e6
                rtts_ms.append(rtt_ms)
                print(f"64 bytes from {dst_ip}: icmp_seq={seq} ttl={reply.ttl} time={rtt_ms:.3f} ms")
                count_recv += 1
            else:
                # Something came back but not an Echo Reply (e.g., an ICMP error)
                print(f"No reply (non-echo response) for icmp_seq {seq}")

        seq += 1
        time.sleep(1)  # 1 Hz per the assignment

if __name__ == "__main__":
    main()