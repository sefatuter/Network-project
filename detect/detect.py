import subprocess
import sys
import time
import re
import platform
import logging
import argparse
import context
from logger import DetectionLogger

parser: argparse.ArgumentParser

def get_gateway_ip():
    """
    Return the system's default gateway IP as a string.
    Uses 'netstat' or 'ip route' to be language independent.
    """
    system = platform.system()
    
    if system == "Windows":
        # 'route print' is better than ipconfig because it uses standard 0.0.0.0 notation
        # regardless of system language (English vs Turkish).
        cmd = ["route", "print", "0.0.0.0"]
        try:
            output = subprocess.check_output(cmd).decode(errors="ignore")
            # Look for the line starting with 0.0.0.0
            # Example: 0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.35     25
            for line in output.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) > 2:
                        # The 3rd column is usually the Gateway in 'route print'
                        context.gateway_ip = parts[2]
                        return
        except Exception as e:
            context.mitm_logger.error(f"[-] Gateway IP tespiti hatasi: {e}")
            
    else:
        # Linux / macOS
        try:
            cmd = ["ip", "route"]
            output = subprocess.check_output(cmd).decode()
            match = re.search(r"default via (\S+)", output)
            if match:
                context.gateway_ip = match.group(1)
                return
        except Exception:
            pass
            
    context.gateway_ip = None 

def get_mac_from_arp(target_ip):
    """
    Returns MAC address of a specific IP from the OS ARP table.
    Refactored to take IP as an argument explicitly.
    """
    cmd = ["arp", "-a"]
    try:
        output = subprocess.check_output(cmd).decode(errors="ignore")
    except subprocess.CalledProcessError:
        return None

    # Regex to find MAC address
    # Supports: 00:11:22... and 00-11-22...
    mac_regex = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"

    for line in output.splitlines():
        # Check if the line contains our target IP
        if target_ip in line:
            mac_match = re.search(mac_regex, line)
            if mac_match:
                # Normalize MAC to standard format (e.g. replace - with :)
                return mac_match.group(0).replace("-", ":").lower()
                
    return None

def monitor_gateway():
    """Sürekli olarak Gateway MAC adresini izler."""
    
    # 1. Gateway IP'yi bul
    get_gateway_ip()
    if not context.gateway_ip:
        context.mitm_logger.error("[-] Gateway IP bulunamadı (Dil sorunu veya ağ hatası).")
        return
    
    context.mitm_logger.info(f"[+] İzlenen Gateway IP: {context.gateway_ip}")

    # 2. İlk (Orijinal) MAC adresini öğren
    initial_mac = get_mac_from_arp(context.gateway_ip)
    
    # Eğer ilk başta bulamazsa bir kez ping atıp tekrar denesin
    if not initial_mac:
        context.mitm_logger.info("[*] Gateway ARP tablosunda yok, ping atılıyor...")
        subprocess.call(["ping", "-n" if platform.system() == "Windows" else "-c", "1", context.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        initial_mac = get_mac_from_arp(context.gateway_ip)

    if initial_mac:
        context.original_mac = initial_mac
        context.mitm_logger.info(f"[+] Orijinal Gateway MAC: {context.original_mac}")
    else:
        context.mitm_logger.error("[-] Gateway MAC adresi tespit edilemedi. Çıkılıyor.")
        return

    # last_mac'i başlangıç değerine eşitle
    last_mac = context.original_mac

    context.mitm_logger.info(f"[*] İzleme Başladı...")
    
    while True:
        try:
            time.sleep(context.interval)
            
            # --- AKTİF KONTROL (PING) ---
            # ARP tablosunu taze tutmak için
            param = "-n" if platform.system().lower() == "windows" else "-c"
            subprocess.call(["ping", param, "1", context.gateway_ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Tabloyu oku
            current_mac = get_mac_from_arp(context.gateway_ip)

            if not current_mac:
                # MAC okunamazsa (ping başarısız vs) atla
                continue

            # Karşılaştırma Mantığı
            if current_mac != context.original_mac:
                context.mitm_logger.critical("!!!" + "="*30 + "!!!")
                context.mitm_logger.critical(f"UYARI: SPOOF TESPİT EDİLDİ!")
                context.mitm_logger.critical(f"Beklenen MAC : {context.original_mac}")
                context.mitm_logger.critical(f"Görülen MAC  : {current_mac}") 
                context.mitm_logger.critical("!!!" + "="*30 + "!!!")
                
                # Uyarıyı sürekli vermemek için current_mac'i güncellemiyoruz
                # Ancak saldırı bitip normale dönerse bunu da loglayabiliriz:
                if last_mac == context.original_mac:
                     # Sadece saldırı yeni başladığında ses çıkar (opsiyonel)
                     pass
            
            elif current_mac == context.original_mac and last_mac != context.original_mac:
                # Saldırı durduysa ve her şey normale döndüyse
                context.mitm_logger.info("[+] ARP Spoofing sona erdi. MAC normale döndü.")

            last_mac = current_mac

        except KeyboardInterrupt:
            break
        except Exception as e:
            context.mitm_logger.error(f"Döngü hatası: {e}")

def setup_arg_parser():
    global parser
    parser = argparse.ArgumentParser(description="Monitor gateway MAC address for changes.")
    parser.add_argument("-i", "--interval", type=int, default=5, help="Interval in seconds (default: 5)")
    parser.add_argument('-c','--console', dest='console', action='store_true', help='Enable console output')
    parser.add_argument('-noc','--no-console', dest='console', action='store_false', help='Disable console output')
    parser.set_defaults(console=True)
    parser.add_argument('-f','--file', dest='file', action='store_true', help='Enable file output')
    parser.add_argument('-nof','--no-file', dest='file', action='store_false', help='Disable file output')
    parser.set_defaults(file=False)

def parse_args():
    args = parser.parse_args()
    context.interval = args.interval
    context.active_handlers = []
    if args.console:
        context.active_handlers.append("console")
    if args.file:
        context.active_handlers.append("file")

def main():
    setup_arg_parser()
    parse_args()
    context.mitm_logger = DetectionLogger.setup_logger()
    monitor_gateway()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)