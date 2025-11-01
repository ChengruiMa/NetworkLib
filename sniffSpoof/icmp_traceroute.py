#!/usr/bin/env python3
"""
icmp_traceroute.py — traceroute implemented with Scapy.

Usage examples:
  python icmp_traceroute.py google.com
  python icmp_traceroute.py 8.8.8.8 --max-hops 30 --timeout 2.0 --probes 3
  # On Windows VM: stop when reply's source == destination

Notes:
- Run with admin/root privileges (raw sockets).
- icmp_traceroute and formattings created with the assistance of GPT 
"""

import argparse
import socket
import sys
import time
from typing import Optional, Tuple, List

from scapy.all import IP, ICMP, sr1, conf  

def reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return ip

def resolve_target(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except Exception as e:
        print(f"Could not resolve {target}: {e}")
        return None

def format_rtt(ms: Optional[float]) -> str:
    return "*" if ms is None else f"{ms:.2f} ms"

def send_probe(dst_ip: str, ttl: int, timeout: float) -> Tuple[Optional[str], Optional[float], Optional[int]]:
    """
    Sends one ICMP Echo probe with given TTL.
    Returns (reply_src_ip, rtt_ms, icmp_type).
    """
    pkt = IP(dst=dst_ip, ttl=ttl) / ICMP()  # ICMP Echo Request
    t0 = time.time()
    reply = sr1(pkt, timeout=timeout, verbose=0)
    if reply is None:
        return None, None, None
    rtt_ms = (time.time() - t0) * 1000.0
    src_ip = reply.src
    icmp_type = reply[ICMP].type if reply.haslayer(ICMP) else None
    return src_ip, rtt_ms, icmp_type

def arrived_at_destination(dst_ip: str,
                           last_src: Optional[str],
                           last_icmp_type: Optional[int],
                           stop_on_dst_src: bool) -> bool:
    """
    For Windows stop as soon as reply source equals destination. 
    Otherwise, stop when we get an ICMP Reply.
    """
    if last_src is None:
        return False
    if stop_on_dst_src and last_src == dst_ip:
        return True
    if last_src == dst_ip and last_icmp_type in (0, 3):
        return True
    return False

def icmp_traceroute(target: str,
                    max_hops: int,
                    timeout: float,
                    probes: int,
                    pause: float,
                    stop_on_dst_src: bool,
                    do_dns: bool) -> None:
    dst_ip = resolve_target(target)
    if not dst_ip:
        return

    print(f"traceroute to {target} ({dst_ip}), {max_hops} hops max, {probes} probe(s) per hop")

    # Faster Scapy send/recv
    conf.verb = 0

    for ttl in range(1, max_hops + 1):
        rtts: List[str] = []
        hop_ips: List[str] = []
        last_src: Optional[str] = None
        last_type: Optional[int] = None

        for p in range(probes):
            src_ip, rtt_ms, icmp_type = send_probe(dst_ip, ttl, timeout)
            rtts.append(format_rtt(rtt_ms))
            if src_ip:
                hop_ips.append(src_ip)
                last_src = src_ip
            last_type = icmp_type
            if pause > 0 and p != probes - 1:
                time.sleep(pause)

        # Pick a representative IP for the hop (if any)
        hop_ip = hop_ips[-1] if hop_ips else None
        hop_name = reverse_dns(hop_ip) if (hop_ip and do_dns) else (hop_ip or "")

        # Output line
        if hop_ip:
            # Show hostname and IP if reverse-DNS changed it
            if do_dns and hop_name != hop_ip:
                id_part = f"{hop_name} ({hop_ip})"
            else:
                id_part = hop_ip
            print(f"{ttl:2d}  {id_part:<40}  {'  '.join(rtts)}")
        else:
            print(f"{ttl:2d}  {'*':<40}  {'  '.join(rtts)}")

        # Check if arrived
        if arrived_at_destination(dst_ip, last_src, last_type, stop_on_dst_src):
            break

def main():
    parser = argparse.ArgumentParser(description="ICMP traceroute implemented with Scapy.")
    parser.add_argument("target", help="Target hostname or IPv4 address (e.g., 8.8.8.8)")
    parser.add_argument("--max-hops", type=int, default=30, help="Max TTL to try (default: 30)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout per probe in seconds (default: 2.0)")
    parser.add_argument("--probes", type=int, default=3, help="Probes per hop (default: 3)")
    parser.add_argument("--pause", type=float, default=0.0, help="Pause between probes (seconds)")
    parser.add_argument("--no-dns", action="store_true", help="Do not perform reverse DNS lookups")
    # Windows quirk: default to True on Windows, False elsewhere (can override).
    default_stop = sys.platform.startswith("win")
    parser.add_argument("--stop-on-dst-src", action="store_true",
                        default=default_stop,
                        help="Stop when a reply's source equals the destination IP (Windows VM workaround)")

    args = parser.parse_args()
    try:
        icmp_traceroute(
            target=args.target,
            max_hops=args.max_hops,
            timeout=args.timeout,
            probes=args.probes,
            pause=args.pause,
            stop_on_dst_src=args.stop_on_dst_src,
            do_dns=not args.no_dns
        )
    except PermissionError:
        print("Permission denied: run this program with administrator/root privileges.")
    except KeyboardInterrupt:
        print("\nInterrupted by user.")

if __name__ == "__main__":
    main()
